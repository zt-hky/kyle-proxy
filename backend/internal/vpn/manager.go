package vpn

import (
	"bufio"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"
)

var sensitiveLogValueRE = regexp.MustCompile(`(?i)(password|passwd|otp|totp|secret|token|cookie|authcookie|portal-userauthcookie|prelogin-cookie|challenge|inputstr)(["'=:\s]+)([^&<>"'\s]+)`)

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
	Portal        string   `json:"portal"`
	Gateway       string   `json:"gateway"`
	Username      string   `json:"username"`
	Password      string   `json:"password"`
	OTP           string   `json:"otp"`
	OTP2          string   `json:"otp2"`
	OTPSecret     string   `json:"otp_secret"`
	AutoReconnect bool     `json:"auto_reconnect"`
	CertFile      string   `json:"cert_file"`
	TrustCert     bool     `json:"trust_cert"` // fetch server cert and pass via --cafile (openconnect v9+)
	ExtraArgs     []string `json:"extra_args,omitempty"`
}

// Status is returned by GetStatus()
type Status struct {
	State            State  `json:"state"`
	Phase            string `json:"phase,omitempty"`
	Detail           string `json:"detail,omitempty"`
	LastLog          string `json:"last_log,omitempty"`
	IP               string `json:"ip,omitempty"`
	Interface        string `json:"interface,omitempty"`
	Error            string `json:"error,omitempty"`
	Since            string `json:"since,omitempty"`
	AwaitingOTP      bool   `json:"awaiting_otp,omitempty"`
	OTPPromptCount   int    `json:"otp_prompt_count,omitempty"`
	AutoOTP          bool   `json:"auto_otp,omitempty"`
	AutoReconnect    bool   `json:"auto_reconnect,omitempty"`
	ReconnectAttempt int    `json:"reconnect_attempt,omitempty"`
}

// Manager manages the VPN lifecycle using gpclient
type Manager struct {
	mu                  sync.RWMutex
	state               State
	errorMsg            string
	cmd                 *exec.Cmd
	stdin               io.WriteCloser
	logs                []string
	connectedAt         time.Time
	tunInterface        string
	phase               string
	detail              string
	lastLog             string
	awaitingOTP         bool
	otpPromptCount      int
	authResponsesSent   int
	credentialPrompts   int
	savedPassword       string
	otpSecret           string
	lastAutoOTPStep     int64
	autoOTPInFlight     bool
	autoReconnect       bool
	reconnectAttempt    int
	stopRequested       bool
	gatewayPasswordSent bool
	sawGatewayLogin     bool
	sawParseError       bool
	onStateChange       func(State)
}

// NewManager creates a new VPN manager
func NewManager() *Manager {
	return &Manager{
		state:           StateDisconnected,
		logs:            make([]string, 0, 500),
		lastAutoOTPStep: -1,
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
		State:            m.state,
		Phase:            m.phase,
		Detail:           m.detail,
		LastLog:          m.lastLog,
		Error:            m.errorMsg,
		Interface:        m.tunInterface,
		AwaitingOTP:      m.awaitingOTP,
		OTPPromptCount:   m.otpPromptCount,
		AutoOTP:          m.otpSecret != "",
		AutoReconnect:    m.autoReconnect,
		ReconnectAttempt: m.reconnectAttempt,
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
	if req.AutoReconnect && strings.TrimSpace(req.OTPSecret) == "" {
		return fmt.Errorf("auto reconnect requires a saved OTP secret")
	}

	m.mu.Lock()
	if m.state == StateConnecting || m.state == StateConnected {
		m.mu.Unlock()
		return fmt.Errorf("VPN already %s", m.state)
	}
	m.stopRequested = false
	m.mu.Unlock()

	m.setState(StateConnecting, "")
	m.setPhase("starting", "Starting VPN connection")
	m.addLog("=== Starting VPN connection ===")

	go func() {
		if err := m.runConnectLoop(req); err != nil {
			m.addLog(fmt.Sprintf("ERROR: %v", err))
			m.setState(StateError, err.Error())
		}
	}()

	return nil
}

// SubmitOTP sends a fresh MFA token to the currently-running openconnect process.
func (m *Manager) SubmitOTP(otp string) error {
	tokens := splitOTPValues(otp)
	if len(tokens) == 0 {
		return fmt.Errorf("OTP is required")
	}

	m.mu.Lock()
	if m.state != StateConnecting {
		m.mu.Unlock()
		return fmt.Errorf("VPN is not awaiting authentication input")
	}
	if !m.awaitingOTP {
		detail := m.detail
		if detail == "" {
			detail = string(m.state)
		}
		m.mu.Unlock()
		return fmt.Errorf("VPN is not waiting for OTP (current step: %s)", detail)
	}
	stdin := m.stdin
	if stdin == nil {
		m.mu.Unlock()
		return fmt.Errorf("VPN authentication input is not available")
	}
	m.awaitingOTP = false
	m.phase = "auth"
	m.detail = "Submitted OTP; waiting for VPN server"
	m.mu.Unlock()

	for _, token := range tokens {
		if _, err := fmt.Fprintf(stdin, "%s\n", token); err != nil {
			return fmt.Errorf("send OTP: %w", err)
		}
		m.recordAuthResponse()
	}
	m.addLog(fmt.Sprintf("MFA: submitted %d OTP response(s)", len(tokens)))
	return nil
}

// Disconnect terminates the VPN connection gracefully
func (m *Manager) Disconnect() error {
	m.mu.Lock()
	m.stopRequested = true
	cmd := m.cmd
	state := m.state
	m.mu.Unlock()

	if state == StateDisconnected || state == StateDisconnecting {
		return nil
	}

	m.setState(StateDisconnecting, "")
	m.addLog("=== Disconnecting VPN ===")

	if cmd != nil && cmd.Process != nil {
		m.mu.Lock()
		stdin := m.stdin
		m.stdin = nil
		m.awaitingOTP = false
		m.mu.Unlock()
		if stdin != nil {
			_ = stdin.Close()
		}

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
	m.stdin = nil
	m.tunInterface = ""
	m.phase = ""
	m.detail = ""
	m.awaitingOTP = false
	m.otpPromptCount = 0
	m.authResponsesSent = 0
	m.credentialPrompts = 0
	m.savedPassword = ""
	m.otpSecret = ""
	m.autoOTPInFlight = false
	m.autoReconnect = false
	m.reconnectAttempt = 0
	m.gatewayPasswordSent = false
	m.sawGatewayLogin = false
	m.sawParseError = false
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
func (m *Manager) runConnectLoop(req ConnectRequest) error {
	req.OTPSecret = strings.TrimSpace(req.OTPSecret)
	req.AutoReconnect = req.AutoReconnect && req.OTPSecret != ""

	attempt := 0
	for {
		m.mu.Lock()
		m.otpSecret = req.OTPSecret
		m.autoReconnect = req.AutoReconnect
		m.reconnectAttempt = attempt
		m.mu.Unlock()

		if attempt > 0 {
			m.addLog(fmt.Sprintf("Auto reconnect: starting attempt %d", attempt))
		}
		err := m.runGPClient(req)
		if err == nil {
			return nil
		}
		if !req.AutoReconnect || !isReconnectableError(err) {
			return err
		}
		if m.isStopped() {
			m.addLog("Auto reconnect: cancelled by disconnect request")
			return nil
		}

		attempt++
		delay := reconnectDelay(attempt)
		m.mu.Lock()
		m.otpSecret = req.OTPSecret
		m.autoReconnect = req.AutoReconnect
		m.reconnectAttempt = attempt
		m.mu.Unlock()
		m.addLog(fmt.Sprintf("Auto reconnect: VPN stopped after being connected; retrying in %s (attempt %d)", delay.Round(time.Second), attempt))
		m.setState(StateConnecting, "")
		m.setPhase("reconnect-wait", fmt.Sprintf("VPN stopped; reconnecting in %s", delay.Round(time.Second)))
		if !m.waitBeforeReconnect(delay) {
			return nil
		}
	}
}

func (m *Manager) submitGeneratedOTP(promptCount int, secret string, stdin io.WriteCloser, afterStep int64) {
	code, wait, err := generateNextTOTP(secret, afterStep, time.Now())
	if err != nil {
		m.failGeneratedOTP(promptCount, stdin, err)
		return
	}

	if wait > 0 {
		m.addLog(fmt.Sprintf("MFA: waiting %s for next OTP window before response #%d", wait.Round(time.Second), promptCount))
		m.setPhase("mfa-auto-wait", fmt.Sprintf("Waiting for next OTP window before response #%d", promptCount))
		if !m.waitForActiveAuth(wait, stdin) {
			return
		}
	}

	m.mu.RLock()
	active := m.state == StateConnecting && m.stdin == stdin
	m.mu.RUnlock()
	if !active {
		return
	}

	if _, err := fmt.Fprintf(stdin, "%s\n", code.Value); err != nil {
		m.failGeneratedOTP(promptCount, stdin, fmt.Errorf("send generated OTP: %w", err))
		return
	}

	m.mu.Lock()
	if m.stdin == stdin {
		m.lastAutoOTPStep = code.Step
		m.autoOTPInFlight = false
		m.authResponsesSent++
		if m.authResponsesSent >= m.otpPromptCount {
			m.awaitingOTP = false
		}
		m.phase = "mfa-auto"
		m.detail = fmt.Sprintf("Submitted generated OTP response #%d; waiting for server", promptCount)
	}
	m.mu.Unlock()
	m.addLog(fmt.Sprintf("MFA: submitted generated OTP response #%d", promptCount))
}

func (m *Manager) failGeneratedOTP(promptCount int, stdin io.WriteCloser, err error) {
	m.mu.Lock()
	if m.stdin == stdin && m.state == StateConnecting {
		m.autoOTPInFlight = false
		m.awaitingOTP = true
		m.phase = "mfa"
		m.detail = fmt.Sprintf("Automatic OTP failed; enter OTP response #%d manually", promptCount)
	}
	m.mu.Unlock()
	m.addLog(fmt.Sprintf("MFA: automatic OTP failed: %v", err))
}

func (m *Manager) waitForActiveAuth(delay time.Duration, stdin io.WriteCloser) bool {
	timer := time.NewTimer(delay)
	defer timer.Stop()

	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-timer.C:
			return true
		case <-ticker.C:
			m.mu.RLock()
			active := m.state == StateConnecting && m.stdin == stdin
			m.mu.RUnlock()
			if !active {
				return false
			}
		}
	}
}

func (m *Manager) runGPClient(req ConnectRequest) error {
	m.addLog(fmt.Sprintf("Connecting to portal: %s (user: %s)", req.Portal, req.Username))
	if err := m.runOpenConnect(req, false); err != nil {
		if m.shouldRetryGatewayDirect() {
			m.addLog("Auth: gateway response could not be parsed; retrying direct gateway mode")
			m.setPhase("gateway-direct", "Retrying direct gateway login; wait for a fresh OTP prompt")
			retryReq := req
			retryReq.OTP = ""
			retryReq.OTP2 = ""
			return m.runOpenConnect(retryReq, true)
		}
		return err
	}
	return nil
}

func (m *Manager) runOpenConnect(req ConnectRequest, directGateway bool) error {
	m.setPhase("preparing", "Preparing openconnect command")

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
		m.setPhase("tls-pin", "Fetching VPN server certificate fingerprint")
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
	if directGateway {
		args = append(args, "--usergroup=gateway")
		m.addLog("Auth: using openconnect gateway-direct mode (--usergroup=gateway)")
	} else if req.Gateway != "" {
		// openconnect connects to the portal first to get config, then gateway.
		// Providing --authgroup selects the gateway if the portal offers multiple.
		args = append(args, "--authgroup="+req.Gateway)
	}
	args = append(args, req.ExtraArgs...)
	args = append(args, server)

	cmd := exec.Command("openconnect", args...)
	cmd.Env = os.Environ()

	// Feed the password and any token supplied at connect time, then keep stdin
	// open so later MFA prompts can be answered with SubmitOTP.
	stdinPipe, err := cmd.StdinPipe()
	if err != nil {
		return fmt.Errorf("stdin pipe: %w", err)
	}
	inputLines := authInputLines(req)

	stdout, _ := cmd.StdoutPipe()
	stderr, _ := cmd.StderrPipe()

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("openconnect start failed: %w", err)
	}
	processStartedAt := time.Now()
	mode := "portal"
	if directGateway {
		mode = "gateway-direct"
	}
	m.addLog(fmt.Sprintf("Trace: openconnect started (pid=%d, mode=%s)", cmd.Process.Pid, mode))

	m.mu.Lock()
	m.cmd = cmd
	m.stdin = stdinPipe
	m.awaitingOTP = false
	m.otpPromptCount = 0
	m.authResponsesSent = 0
	m.credentialPrompts = 0
	m.savedPassword = req.Password
	m.otpSecret = strings.TrimSpace(req.OTPSecret)
	m.autoReconnect = req.AutoReconnect && m.otpSecret != ""
	m.autoOTPInFlight = false
	m.gatewayPasswordSent = false
	m.sawGatewayLogin = false
	m.sawParseError = false
	m.mu.Unlock()

	switch {
	case m.otpSecret != "":
		m.setPhase("auth", "Submitting saved password; OTP will be generated when requested")
	case len(inputLines) > 1:
		m.setPhase("auth", "Submitting saved password and initial OTP")
	default:
		m.setPhase("auth", "Submitting saved password")
	}
	if err := m.writeInitialAuth(stdinPipe, inputLines); err != nil {
		_ = stdinPipe.Close()
		m.clearProcessAuthState()
		return err
	}

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

	waitErr := cmd.Wait()
	m.mu.RLock()
	currentState := m.state
	tunnelEstablished := m.connectedAt.After(processStartedAt)
	stopRequested := m.stopRequested
	m.mu.RUnlock()
	processResult := "exit-code-0"
	if waitErr != nil {
		processResult = waitErr.Error()
	}
	m.addLog(fmt.Sprintf(
		"Trace: openconnect exited (pid=%d, runtime=%s, state=%s, tunnel_established=%t, stop_requested=%t, result=%s)",
		cmd.Process.Pid,
		time.Since(processStartedAt).Round(time.Millisecond),
		currentState,
		tunnelEstablished,
		stopRequested,
		processResult,
	))
	m.clearProcessAuthState()
	exitErr := classifyOpenConnectExit(waitErr, currentState, tunnelEstablished, stopRequested)
	if isReconnectableError(exitErr) {
		m.setState(StateDisconnected, "")
	} else if exitErr == nil && !stopRequested && currentState != StateDisconnecting {
		m.setState(StateDisconnected, "")
	}
	return exitErr
}

// streamOutput reads process output line by line, logs it, and detects state transitions
func (m *Manager) streamOutput(r io.Reader) {
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := sanitizeLogLine(scanner.Text())
		m.addLog(line)

		lower := strings.ToLower(line)
		m.updatePhaseFromLine(lower)
		if isCredentialPromptLine(lower) {
			m.noteCredentialPrompt()
		}
		if isOTPPromptLine(lower) {
			m.noteOTPPrompt()
		}
		switch {
		case isVPNEstablishedLine(lower):
			iface := detectTunInterface()
			m.mu.Lock()
			m.state = StateConnected
			m.connectedAt = time.Now()
			m.tunInterface = iface
			m.awaitingOTP = false
			m.phase = "connected"
			m.detail = "VPN tunnel established"
			reconnectAttempt := m.reconnectAttempt
			cb := m.onStateChange
			m.mu.Unlock()
			if reconnectAttempt > 0 {
				m.addLog(fmt.Sprintf("Auto reconnect: attempt %d established the VPN tunnel", reconnectAttempt))
			}
			if iface != "" {
				m.addLog(fmt.Sprintf("Tunnel up on interface: %s", iface))
			} else {
				m.addLog("Tunnel established; interface not detected yet")
			}
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

func (m *Manager) writeInitialAuth(stdin io.Writer, lines []string) error {
	if len(lines) == 0 {
		return nil
	}
	if _, err := fmt.Fprintf(stdin, "%s\n", lines[0]); err != nil {
		return fmt.Errorf("send password: %w", err)
	}
	for _, token := range lines[1:] {
		if _, err := fmt.Fprintf(stdin, "%s\n", token); err != nil {
			return fmt.Errorf("send initial OTP: %w", err)
		}
		m.recordAuthResponse()
	}
	if len(lines) > 1 {
		m.addLog(fmt.Sprintf("MFA: submitted %d initial OTP response(s)", len(lines)-1))
	}
	return nil
}

func (m *Manager) updatePhaseFromLine(lower string) {
	switch {
	case strings.Contains(lower, "/global-protect/prelogin"):
		m.setPhase("portal-prelogin", "Contacting GlobalProtect portal")
	case strings.Contains(lower, "/global-protect/getconfig"):
		m.setPhase("portal-config", "Fetching portal configuration")
	case strings.Contains(lower, "please select globalprotect gateway"):
		m.setPhase("gateway-select", "Selecting GlobalProtect gateway")
	case strings.Contains(lower, "/ssl-vpn/prelogin"):
		m.setPhase("gateway-prelogin", "Contacting selected gateway")
	case strings.Contains(lower, "/ssl-vpn/login"):
		m.markGatewayLoginAttempt()
	case isPasswordPromptLine(lower):
		m.setPhase("gateway-password", "Gateway password prompt is active")
	case strings.Contains(lower, "failed to parse server response"):
		m.markParseError()
	case containsAny(lower, "unexpected 512 result from server", "status code 512"):
		m.setPhase("auth-challenge", "Server returned another authentication challenge")
	case strings.Contains(lower, "ssl negotiation"):
		m.setPhase("tls-handshake", "Negotiating TLS with gateway")
	case strings.Contains(lower, "connected to https"):
		m.setPhase("tls-connected", "TLS connected; VPN tunnel is not established yet")
	case strings.Contains(lower, "server certificate verify failed"):
		m.setPhase("tls-warning", "Server certificate is pinned; continuing TLS handshake")
	case strings.Contains(lower, "failed to complete authentication"):
		m.setPhase("auth-failed", "Authentication failed")
	case strings.Contains(lower, "user input required in non-interactive mode"):
		m.setPhase("input-required", "VPN client needs another authentication response")
	}
}

func (m *Manager) markGatewayLoginAttempt() {
	m.mu.Lock()
	m.sawGatewayLogin = true
	m.phase = "gateway-login"
	m.detail = "Submitting authentication to gateway"
	m.mu.Unlock()
}

func (m *Manager) markParseError() {
	m.mu.Lock()
	m.sawParseError = true
	m.phase = "auth-parse-error"
	m.detail = "Gateway returned an authentication response openconnect could not parse"
	m.awaitingOTP = false
	m.mu.Unlock()
}

func (m *Manager) shouldRetryGatewayDirect() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.sawGatewayLogin && m.sawParseError
}

func (m *Manager) noteCredentialPrompt() {
	m.mu.Lock()
	m.credentialPrompts++
	count := m.credentialPrompts
	if count == 1 {
		m.phase = "portal-auth"
		m.detail = "Submitting portal credentials"
		m.mu.Unlock()
		return
	}

	stdin := m.stdin
	password := m.savedPassword
	shouldSendGatewayPassword := !m.gatewayPasswordSent && password != "" && stdin != nil
	if shouldSendGatewayPassword {
		m.gatewayPasswordSent = true
		m.awaitingOTP = false
		m.phase = "gateway-auth"
		m.detail = "Gateway requested password; submitting saved password"
	} else {
		m.awaitingOTP = false
		m.phase = "gateway-auth"
		switch {
		case password == "":
			m.detail = "Gateway requested credentials, but no saved password is configured"
		case m.gatewayPasswordSent:
			m.detail = "Gateway requested credentials again; waiting for an explicit OTP/password prompt"
		default:
			m.detail = "Gateway requested credentials; waiting for an explicit prompt"
		}
	}
	m.mu.Unlock()

	if shouldSendGatewayPassword {
		if _, err := fmt.Fprintf(stdin, "%s\n", password); err != nil {
			m.addLog(fmt.Sprintf("Auth: failed to submit saved gateway password: %v", err))
			return
		}
		m.addLog("Auth: gateway requested password; submitted saved password (not OTP)")
		return
	}
	m.addLog("Auth: gateway credential prompt detected; not treating it as OTP")
}

func (m *Manager) recordAuthResponse() {
	m.mu.Lock()
	m.authResponsesSent++
	if m.authResponsesSent >= m.otpPromptCount {
		m.awaitingOTP = false
	}
	m.mu.Unlock()
}

func (m *Manager) noteOTPPrompt() {
	var (
		autoSecret  string
		stdin       io.WriteCloser
		promptCount int
		afterStep   int64
		needsInput  bool
	)

	m.mu.Lock()
	if m.awaitingOTP || m.autoOTPInFlight {
		m.phase = "mfa"
		if m.autoOTPInFlight {
			m.detail = fmt.Sprintf("Generating OTP response #%d", m.otpPromptCount)
		} else {
			m.detail = fmt.Sprintf("Waiting for fresh OTP response #%d", m.otpPromptCount)
		}
		m.mu.Unlock()
		return
	}
	m.otpPromptCount++
	promptCount = m.otpPromptCount
	needsInput = m.authResponsesSent < promptCount
	if needsInput {
		autoSecret = strings.TrimSpace(m.otpSecret)
		stdin = m.stdin
		afterStep = m.lastAutoOTPStep
		if autoSecret != "" && stdin != nil {
			m.awaitingOTP = false
			m.autoOTPInFlight = true
			m.phase = "mfa-auto"
			m.detail = fmt.Sprintf("Generating OTP response #%d", promptCount)
		} else {
			m.awaitingOTP = true
			m.phase = "mfa"
			m.detail = fmt.Sprintf("Waiting for fresh OTP response #%d", promptCount)
		}
	} else {
		m.phase = "mfa"
		m.detail = fmt.Sprintf("Submitted OTP response #%d; waiting for server", promptCount)
	}
	m.mu.Unlock()

	if needsInput {
		if autoSecret != "" && stdin != nil {
			m.addLog(fmt.Sprintf("MFA: generating OTP response #%d from saved TOTP secret", promptCount))
			go m.submitGeneratedOTP(promptCount, autoSecret, stdin, afterStep)
			return
		}
		m.addLog(fmt.Sprintf("MFA: waiting for fresh OTP response #%d", promptCount))
	}
}

func (m *Manager) clearProcessAuthState() {
	m.mu.Lock()
	m.cmd = nil
	m.stdin = nil
	m.awaitingOTP = false
	m.otpPromptCount = 0
	m.authResponsesSent = 0
	m.credentialPrompts = 0
	m.savedPassword = ""
	m.otpSecret = ""
	m.autoOTPInFlight = false
	m.autoReconnect = false
	m.gatewayPasswordSent = false
	m.mu.Unlock()
}

func (m *Manager) setPhase(phase, detail string) {
	m.mu.Lock()
	m.phase = phase
	m.detail = detail
	m.mu.Unlock()
}

// setState safely updates state and fires the callback
func (m *Manager) setState(s State, errMsg string) {
	m.mu.Lock()
	m.state = s
	m.errorMsg = errMsg
	if s == StateDisconnected {
		m.phase = ""
		m.detail = ""
		m.awaitingOTP = false
	}
	if s == StateError && errMsg != "" {
		m.phase = "error"
		m.detail = errMsg
		m.awaitingOTP = false
	}
	cb := m.onStateChange
	m.mu.Unlock()
	if cb != nil {
		cb(s)
	}
}

// addLog appends a timestamped log line (capped at 500 lines)
func (m *Manager) addLog(line string) {
	line = sanitizeLogLine(line)
	ts := time.Now().Format("15:04:05")
	entry := fmt.Sprintf("[%s] %s", ts, line)
	log.Printf("[VPN] %s", line)

	m.mu.Lock()
	defer m.mu.Unlock()
	m.lastLog = line
	m.logs = append(m.logs, entry)
	if len(m.logs) > 500 {
		m.logs = m.logs[len(m.logs)-500:]
	}
}

func sanitizeLogLine(line string) string {
	lower := strings.ToLower(line)
	for _, header := range []string{"cookie:", "set-cookie:", "authorization:"} {
		if idx := strings.Index(lower, header); idx >= 0 {
			return line[:idx+len(header)] + " [redacted]"
		}
	}
	return sensitiveLogValueRE.ReplaceAllString(line, "$1$2[redacted]")
}

// detectTunInterface finds the tun/gpd interface created by gpclient
func detectTunInterface() string {
	for i := 0; i < 10; i++ {
		ifaces, _ := net.Interfaces()
		for _, iface := range ifaces {
			n := iface.Name
			if isVPNInterfaceName(n) {
				return n
			}
		}
		time.Sleep(300 * time.Millisecond)
	}
	return ""
}

func isVPNInterfaceName(name string) bool {
	if strings.HasPrefix(name, "gpd-") || strings.HasPrefix(name, "utun") {
		return true
	}
	if strings.HasPrefix(name, "tun") {
		if len(name) == 3 {
			return true
		}
		return name[3] >= '0' && name[3] <= '9'
	}
	return false
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

type reconnectableVPNError struct {
	err error
}

func (e reconnectableVPNError) Error() string {
	return e.err.Error()
}

func (e reconnectableVPNError) Unwrap() error {
	return e.err
}

func isReconnectableError(err error) bool {
	var target reconnectableVPNError
	return errors.As(err, &target)
}

func classifyOpenConnectExit(waitErr error, currentState State, tunnelEstablished, stopRequested bool) error {
	if stopRequested || currentState == StateDisconnecting {
		return nil
	}
	if tunnelEstablished {
		if waitErr != nil {
			return reconnectableVPNError{err: fmt.Errorf("openconnect exited after tunnel was established: %w", waitErr)}
		}
		return reconnectableVPNError{err: fmt.Errorf("openconnect exited after tunnel was established")}
	}
	if waitErr != nil {
		return fmt.Errorf("openconnect exited before tunnel was established: %w", waitErr)
	}
	return nil
}

func reconnectDelay(attempt int) time.Duration {
	if attempt <= 1 {
		return 5 * time.Second
	}
	delay := time.Duration(attempt*5) * time.Second
	if delay > time.Minute {
		return time.Minute
	}
	return delay
}

func (m *Manager) waitBeforeReconnect(delay time.Duration) bool {
	timer := time.NewTimer(delay)
	defer timer.Stop()

	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-timer.C:
			return !m.isStopped()
		case <-ticker.C:
			if m.isStopped() {
				return false
			}
		}
	}
}

func (m *Manager) isStopped() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.stopRequested
}

func authInputLines(req ConnectRequest) []string {
	lines := []string{req.Password}
	return append(lines, otpInputs(req.OTP, req.OTP2)...)
}

func otpInputs(values ...string) []string {
	inputs := make([]string, 0, len(values))
	for _, value := range values {
		for _, token := range splitOTPValues(value) {
			inputs = append(inputs, token)
		}
	}
	return inputs
}

func isOTPPromptLine(lower string) bool {
	return strings.Contains(lower, "otp") &&
		(strings.Contains(lower, "enter") || strings.Contains(lower, "please") || strings.Contains(lower, "value"))
}

func isCredentialPromptLine(lower string) bool {
	return strings.Contains(lower, "enter login credentials")
}

func isPasswordPromptLine(lower string) bool {
	return strings.HasPrefix(strings.TrimSpace(lower), "password:")
}

func isVPNEstablishedLine(lower string) bool {
	return containsAny(lower,
		"vpn connection established",
		"esp session established",
		"cstp connected",
		"connected as ",
		"configured as ",
		"tunnel is up",
	)
}

func splitOTPValues(value string) []string {
	parts := strings.FieldsFunc(value, func(r rune) bool {
		return r == ',' || r == ';' || r == '\n' || r == '\r'
	})
	tokens := make([]string, 0, len(parts))
	for _, part := range parts {
		token := strings.TrimSpace(part)
		if token != "" {
			tokens = append(tokens, token)
		}
	}
	return tokens
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
