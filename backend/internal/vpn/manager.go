package vpn

import (
	"bufio"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"time"
)

// State represents VPN connection state
type State string

const (
	StateDisconnected  State = "disconnected"
	StateConnecting    State = "connecting"
	StateConnected     State = "connected"
	StateDisconnecting State = "disconnecting"
	StateError         State = "error"
)

// ConnectRequest holds runtime credentials (OTP is one-time, not stored)
type ConnectRequest struct {
	Portal    string `json:"portal"`
	Gateway   string `json:"gateway"`
	Username  string `json:"username"`
	Password  string `json:"password"`
	OTP       string `json:"otp"`
	CertFile  string `json:"cert_file"`
	TrustCert bool   `json:"trust_cert"` // fetch server cert and pass via --cafile (openconnect v9+)
}

// Status is returned by GetStatus()
type Status struct {
	State     State  `json:"state"`
	IP        string `json:"ip,omitempty"`
	Interface string `json:"interface,omitempty"`
	Error     string `json:"error,omitempty"`
	Since     string `json:"since,omitempty"`
}

// Manager manages the VPN lifecycle using gpclient
type Manager struct {
	mu            sync.RWMutex
	state         State
	errorMsg      string
	cmd           *exec.Cmd
	logs          []string
	connectedAt   time.Time
	tunInterface  string
	onStateChange func(State)
}

// NewManager creates a new VPN manager
func NewManager() *Manager {
	return &Manager{
		state: StateDisconnected,
		logs:  make([]string, 0, 500),
	}
}

// OnStateChange registers a callback triggered when state changes
func (m *Manager) OnStateChange(fn func(State)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.onStateChange = fn
}

// GetStatus returns the current VPN status
func (m *Manager) GetStatus() Status {
	m.mu.RLock()
	defer m.mu.RUnlock()

	s := Status{
		State:    m.state,
		Error:    m.errorMsg,
		Interface: m.tunInterface,
	}

	if m.state == StateConnected && !m.connectedAt.IsZero() {
		s.Since = m.connectedAt.Format(time.RFC3339)
		if m.tunInterface != "" {
			s.IP = getInterfaceIP(m.tunInterface)
		}
	}
	return s
}

// GetLogs returns a copy of recent log lines
func (m *Manager) GetLogs() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	result := make([]string, len(m.logs))
	copy(result, m.logs)
	return result
}

// Connect initiates a VPN connection asynchronously
func (m *Manager) Connect(req ConnectRequest) error {
	m.mu.Lock()
	if m.state == StateConnecting || m.state == StateConnected {
		m.mu.Unlock()
		return fmt.Errorf("VPN already %s", m.state)
	}
	m.mu.Unlock()

	m.setState(StateConnecting, "")
	m.addLog("=== Starting VPN connection ===")

	go func() {
		if err := m.runGPClient(req); err != nil {
			m.addLog(fmt.Sprintf("ERROR: %v", err))
			m.setState(StateError, err.Error())
		}
	}()

	return nil
}

// Disconnect terminates the VPN connection gracefully
func (m *Manager) Disconnect() error {
	m.mu.Lock()
	cmd := m.cmd
	state := m.state
	m.mu.Unlock()

	if state == StateDisconnected || state == StateDisconnecting {
		return nil
	}

	m.setState(StateDisconnecting, "")
	m.addLog("=== Disconnecting VPN ===")

	if cmd != nil && cmd.Process != nil {
		// Try graceful SIGTERM first
		if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
			log.Printf("[VPN] SIGTERM failed, killing process: %v", err)
			_ = cmd.Process.Kill()
		}

		// Force kill after 8 seconds
		done := make(chan struct{})
		go func() {
			defer close(done)
			_ = cmd.Wait()
		}()

		select {
		case <-done:
			m.addLog("gpclient stopped")
		case <-time.After(8 * time.Second):
			_ = cmd.Process.Kill()
			m.addLog("gpclient force-killed after timeout")
		}
	}

	m.mu.Lock()
	m.cmd = nil
	m.tunInterface = ""
	m.mu.Unlock()

	m.setState(StateDisconnected, "")
	m.addLog("=== VPN disconnected ===")
	return nil
}

// runGPClient connects to GlobalProtect VPN using openconnect --protocol=gp.
//
// openconnect is the underlying engine used by GlobalProtect-openconnect.
// It supports non-interactive auth via --user / --passwd and handles
// password-based + OTP (TOTP/SecurID) flows reliably in headless mode.
//
// Auth sequence openconnect uses for GlobalProtect:
//  1. POST to /ssl-vpn/prelogin.esp  (portal pre-login)
//  2. POST to /ssl-vpn/login.esp     (submit credentials → receive cookie)
//  3. POST to /ssl-vpn/getconfig.esp (fetch gateway list)
//  4. Connect to chosen gateway via DTLS/TLS
func (m *Manager) runGPClient(req ConnectRequest) error {
	m.addLog(fmt.Sprintf("Connecting to portal: %s (user: %s)", req.Portal, req.Username))

	// Build openconnect argument list
	// --protocol=gp         → GlobalProtect protocol
	// --user                → username
	// --passwd-on-stdin     → read password (and OTP if prompted) from stdin
	// --non-inter           → no interactive prompts (fail instead)
	// --no-dtls             → force TLS (more compatible; remove for UDP perf)
	// --background          → daemonise after auth (not used; we watch stdout)
	args := []string{
		"--protocol=gp",
		"--user=" + req.Username,
		"--passwd-on-stdin",
		"--non-inter",
		"--script=/usr/share/vpnc-scripts/vpnc-script", // sets routes/DNS after tunnel up (Debian path)
		"--no-proxy",
	}

	// When TrustCert is set, bypass cert hostname/CA validation by pinning the
	// server's own leaf certificate. openconnect v9+ removed --no-certificate-check;
	// --servercert pin-sha256:<base64> is the correct replacement — it tells
	// openconnect to accept exactly this cert regardless of hostname or CA chain.
	if req.TrustCert {
		m.addLog("⚠️  TrustCert: fetching server certificate fingerprint...")
		pin, err := fetchServerCertPin(req.Portal)
		if err != nil {
			m.addLog(fmt.Sprintf("⚠️  Could not fetch server cert: %v — continuing without pin", err))
		} else {
			args = append(args, "--servercert="+pin)
			m.addLog(fmt.Sprintf("⚠️  TLS: pinning via --servercert=%s", pin))
		}
	}

	// Custom CA cert for TLS verification (explicit override)
	if req.CertFile != "" {
		args = append(args, "--cafile="+req.CertFile)
	}

	// Explicit gateway takes priority over portal for the tunnel endpoint
	server := req.Portal
	if req.Gateway != "" {
		// openconnect connects to the portal first to get config, then gateway.
		// Providing --authgroup selects the gateway if the portal offers multiple.
		args = append(args, "--authgroup="+req.Gateway)
	}
	args = append(args, server)

	cmd := exec.Command("openconnect", args...)
	cmd.Env = os.Environ()

	// Feed credentials via stdin:
	//   Line 1 → password
	//   Line 2 → OTP/token (only sent if OTP is non-empty; openconnect will
	//             prompt for it automatically when the server requests MFA)
	stdinPipe, err := cmd.StdinPipe()
	if err != nil {
		return fmt.Errorf("stdin pipe: %w", err)
	}
	go func() {
		defer stdinPipe.Close()
		fmt.Fprintf(stdinPipe, "%s\n", req.Password)
		if req.OTP != "" {
			// Wait for server to respond to password and issue the OTP challenge
			time.Sleep(1 * time.Second)
			fmt.Fprintf(stdinPipe, "%s\n", req.OTP)
		}
	}()

	stdout, _ := cmd.StdoutPipe()
	stderr, _ := cmd.StderrPipe()

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("openconnect start failed: %w", err)
	}

	m.mu.Lock()
	m.cmd = cmd
	m.mu.Unlock()

	// Stream stdout and stderr, detect state changes
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		m.streamOutput(stdout)
	}()
	go func() {
		defer wg.Done()
		m.streamOutput(stderr)
	}()
	wg.Wait()

	if err := cmd.Wait(); err != nil {
		// Check if disconnection was intentional
		m.mu.RLock()
		currentState := m.state
		m.mu.RUnlock()
		if currentState == StateDisconnecting || currentState == StateDisconnected {
			return nil
		}
		return fmt.Errorf("gpclient exited: %w", err)
	}

	m.setState(StateDisconnected, "")
	return nil
}

// streamOutput reads process output line by line, logs it, and detects state transitions
func (m *Manager) streamOutput(r io.Reader) {
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Text()
		m.addLog(line)
		log.Printf("[VPN] %s", line)

		lower := strings.ToLower(line)
		switch {
		case containsAny(lower, "connected", "tunnel is up", "established", "vpn connection established"):
			iface := detectTunInterface()
			m.mu.Lock()
			m.state = StateConnected
			m.connectedAt = time.Now()
			m.tunInterface = iface
			cb := m.onStateChange
			m.mu.Unlock()
			m.addLog(fmt.Sprintf("Tunnel up on interface: %s", iface))
			if cb != nil {
				cb(StateConnected)
			}
		case containsAny(lower, "disconnected", "connection terminated", "bye"):
			m.mu.RLock()
			s := m.state
			m.mu.RUnlock()
			if s != StateDisconnecting {
				m.setState(StateDisconnected, "")
			}
		}
	}
}

// setState safely updates state and fires the callback
func (m *Manager) setState(s State, errMsg string) {
	m.mu.Lock()
	m.state = s
	m.errorMsg = errMsg
	cb := m.onStateChange
	m.mu.Unlock()
	if cb != nil {
		cb(s)
	}
}

// addLog appends a timestamped log line (capped at 500 lines)
func (m *Manager) addLog(line string) {
	ts := time.Now().Format("15:04:05")
	entry := fmt.Sprintf("[%s] %s", ts, line)
	log.Printf("[VPN] %s", line)

	m.mu.Lock()
	defer m.mu.Unlock()
	m.logs = append(m.logs, entry)
	if len(m.logs) > 500 {
		m.logs = m.logs[len(m.logs)-500:]
	}
}

// detectTunInterface finds the tun/gpd interface created by gpclient
func detectTunInterface() string {
	for i := 0; i < 10; i++ {
		ifaces, _ := net.Interfaces()
		for _, iface := range ifaces {
			n := iface.Name
			if strings.HasPrefix(n, "tun") || strings.HasPrefix(n, "gpd-") || strings.HasPrefix(n, "utun") {
				return n
			}
		}
		time.Sleep(300 * time.Millisecond)
	}
	return "tun0" // default fallback
}

// getInterfaceIP returns the first IPv4 address of the given interface
func getInterfaceIP(ifaceName string) string {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return ""
	}
	addrs, _ := iface.Addrs()
	for _, addr := range addrs {
		switch v := addr.(type) {
		case *net.IPNet:
			if ip := v.IP.To4(); ip != nil {
				return ip.String()
			}
		case *net.IPAddr:
			if ip := v.IP.To4(); ip != nil {
				return ip.String()
			}
		}
	}
	return ""
}

func containsAny(s string, substrs ...string) bool {
	for _, sub := range substrs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

// fetchServerCertPin dials host over TLS (skipping verification), grabs the leaf
// certificate, and returns an openconnect --servercert fingerprint of the form:
//
//	pin-sha256:<base64-std-encoded-sha256-of-DER>
//
// This is the correct way to bypass cert validation in openconnect v9+, which
// removed the old --no-certificate-check flag. The pin locks openconnect to
// accept exactly this server certificate regardless of hostname or CA chain.
func fetchServerCertPin(host string) (string, error) {
	addr := host
	if !strings.Contains(host, ":") {
		addr = host + ":443"
	}

	conn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: 10 * time.Second},
		"tcp", addr,
		&tls.Config{
			InsecureSkipVerify: true, //nolint:gosec // intentional: user opted in via TrustCert
		},
	)
	if err != nil {
		return "", fmt.Errorf("TLS dial %s: %w", addr, err)
	}
	defer conn.Close()

	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return "", fmt.Errorf("no certificates returned by %s", addr)
	}

	// openconnect pin-sha256 is SHA256 of SubjectPublicKeyInfo (SPKI), NOT full cert DER
	digest := sha256.Sum256(certs[0].RawSubjectPublicKeyInfo)
	return "pin-sha256:" + base64.StdEncoding.EncodeToString(digest[:]), nil
}
