package vpn

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestOpenConnectHelper(t *testing.T) {
	mode := ""
	for _, arg := range os.Args {
		if strings.HasPrefix(arg, "helper-mode=") {
			mode = strings.TrimPrefix(arg, "helper-mode=")
		}
	}
	if mode == "" {
		return
	}
	switch mode {
	case "success":
		fmt.Fprintln(os.Stdout, "POST /global-protect/prelogin")
		fmt.Fprintln(os.Stdout, "POST /global-protect/getconfig")
		fmt.Fprintln(os.Stdout, "Please select GlobalProtect gateway")
		fmt.Fprintln(os.Stdout, "POST /ssl-vpn/prelogin")
		fmt.Fprintln(os.Stdout, "POST /ssl-vpn/login")
		fmt.Fprintln(os.Stdout, "Password:")
		fmt.Fprintln(os.Stdout, "SSL negotiation")
		fmt.Fprintln(os.Stdout, "Connected to HTTPS")
		fmt.Fprintln(os.Stdout, "VPN connection established")
	case "parse":
		fmt.Fprintln(os.Stderr, "POST /ssl-vpn/login")
		fmt.Fprintln(os.Stderr, "Failed to parse server response")
		os.Exit(2)
	case "fail":
		os.Exit(3)
	case "sleep":
		time.Sleep(30 * time.Second)
	}
	os.Exit(0)
}

func helperCommand(mode string) func(string, ...string) *exec.Cmd {
	return func(string, ...string) *exec.Cmd {
		return exec.Command(os.Args[0], "-test.run=TestOpenConnectHelper", "--", "helper-mode="+mode)
	}
}

func TestRunOpenConnectSuccessAndFailures(t *testing.T) {
	old := execCommand
	defer func() { execCommand = old }()
	req := ConnectRequest{Portal: "vpn.example", Username: "user", Password: "pw", OTP: "111111", OTP2: "222222", Gateway: "gw", CertFile: "ca.pem", ExtraArgs: []string{"--verbose"}}
	execCommand = helperCommand("success")
	m := NewManager()
	m.setState(StateConnecting, "")
	if err := m.runOpenConnect(req, false); !isReconnectableError(err) {
		t.Fatalf("established exit: %v", err)
	}
	if got := m.GetStatus(); got.State != StateDisconnected {
		t.Fatalf("state=%s", got.State)
	}
	if len(m.GetLogs()) == 0 {
		t.Fatal("expected logs")
	}

	execCommand = func(string, ...string) *exec.Cmd { return exec.Command("/definitely/missing/openconnect") }
	if err := NewManager().runOpenConnect(req, false); err == nil || !strings.Contains(err.Error(), "start failed") {
		t.Fatalf("start err=%v", err)
	}

	execCommand = func(string, ...string) *exec.Cmd {
		c := exec.Command(os.Args[0], "-test.run=TestOpenConnectHelper")
		c.Stdin = strings.NewReader("")
		return c
	}
	if err := NewManager().runOpenConnect(req, false); err == nil || !strings.Contains(err.Error(), "stdin pipe") {
		t.Fatalf("pipe err=%v", err)
	}

	execCommand = helperCommand("fail")
	if err := NewManager().runOpenConnect(req, true); err == nil || isReconnectableError(err) {
		t.Fatalf("pre-tunnel err=%v", err)
	}
}

func TestRunGPClientGatewayRetry(t *testing.T) {
	old := execCommand
	defer func() { execCommand = old }()
	calls := 0
	execCommand = func(string, ...string) *exec.Cmd {
		calls++
		if calls == 1 {
			return helperCommand("parse")("openconnect")
		}
		return helperCommand("success")("openconnect")
	}
	m := NewManager()
	m.setState(StateConnecting, "")
	if err := m.runGPClient(ConnectRequest{Portal: "vpn", Password: "pw", OTP: "123", OTP2: "456"}); !isReconnectableError(err) {
		t.Fatalf("gateway retry result: %v", err)
	}
	if calls != 2 {
		t.Fatalf("calls=%d", calls)
	}
}

func TestDisconnectRunningProcessAndStateBranches(t *testing.T) {
	old := execCommand
	defer func() { execCommand = old }()
	execCommand = helperCommand("sleep")
	cmd := execCommand("openconnect")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	m := NewManager()
	m.mu.Lock()
	m.state = StateConnected
	m.cmd = cmd
	m.stdin = stdin
	m.awaitingOTP = true
	m.autoReconnect = true
	m.mu.Unlock()
	if err = m.Disconnect(); err != nil {
		t.Fatal(err)
	}
	if s := m.GetStatus(); s.State != StateDisconnected || s.AwaitingOTP || s.AutoReconnect {
		t.Fatalf("status=%+v", s)
	}
	if err = m.Disconnect(); err != nil {
		t.Fatal(err)
	}
	m.mu.Lock()
	m.state = StateDisconnecting
	m.mu.Unlock()
	if err = m.Disconnect(); err != nil {
		t.Fatal(err)
	}
}

func TestStreamPhasesPromptsAndDisconnect(t *testing.T) {
	m := NewManager()
	m.mu.Lock()
	m.state = StateConnecting
	m.savedPassword = "pw"
	m.stdin = &bufferWriteCloser{}
	m.reconnectAttempt = 2
	m.mu.Unlock()
	lines := []string{"/global-protect/prelogin", "/global-protect/getconfig", "Please select GlobalProtect gateway", "/ssl-vpn/prelogin", "/ssl-vpn/login", "Password:", "unexpected 512 result from server", "SSL negotiation", "connected to https", "server certificate verify failed", "failed to complete authentication", "user input required in non-interactive mode", "Enter login credentials", "Enter login credentials", "Enter login credentials", "Please enter OTP value", "Please enter OTP value", "failed to parse server response", "disconnected"}
	m.streamOutput(strings.NewReader(strings.Join(lines, "\n") + "\n"))
	s := m.GetStatus()
	if s.State != StateDisconnected {
		t.Fatalf("status=%+v", s)
	}
	if !m.shouldRetryGatewayDirect() {
		t.Fatal("expected direct retry")
	}
	m.mu.Lock()
	m.state = StateDisconnecting
	m.mu.Unlock()
	m.streamOutput(strings.NewReader("bye\n"))
	if m.GetStatus().State != StateDisconnecting {
		t.Fatal("disconnecting state changed")
	}
}

func TestGeneratedOTPAndAuthWaitPaths(t *testing.T) {
	m := NewManager()
	out := &bufferWriteCloser{}
	m.mu.Lock()
	m.state = StateConnecting
	m.stdin = out
	m.otpPromptCount = 1
	m.autoOTPInFlight = true
	m.mu.Unlock()
	m.submitGeneratedOTP(1, "JBSWY3DPEHPK3PXP", out, -1)
	if strings.TrimSpace(out.String()) == "" {
		t.Fatal("no generated OTP")
	}
	bad := &bufferWriteCloser{}
	m.mu.Lock()
	m.stdin = bad
	m.autoOTPInFlight = true
	m.mu.Unlock()
	m.submitGeneratedOTP(2, "bad!", bad, -1)
	if !m.GetStatus().AwaitingOTP {
		t.Fatal("expected manual fallback")
	}
	m.mu.Lock()
	m.stdin = out
	m.state = StateConnecting
	m.mu.Unlock()
	if !m.waitForActiveAuth(time.Millisecond, out) {
		t.Fatal("timer path")
	}
	m.mu.Lock()
	m.state = StateDisconnected
	m.mu.Unlock()
	if m.waitForActiveAuth(600*time.Millisecond, out) {
		t.Fatal("inactive path")
	}
}

func TestAuthWritesLogsClassificationAndReconnect(t *testing.T) {
	m := NewManager()
	if err := m.writeInitialAuth(io.Discard, nil); err != nil {
		t.Fatal(err)
	}
	fail := errorWriteCloser{err: errors.New("write")}
	if err := m.writeInitialAuth(fail, []string{"pw"}); err == nil || !strings.Contains(err.Error(), "password") {
		t.Fatalf("%v", err)
	}
	w := &failAfterWriter{remaining: 1}
	if err := m.writeInitialAuth(w, []string{"pw", "otp"}); err == nil || !strings.Contains(err.Error(), "initial OTP") {
		t.Fatalf("%v", err)
	}
	m.addLog("password=secret authorization: Bearer abc")
	logs := m.GetLogs()
	if strings.Contains(strings.Join(logs, ""), "secret") || strings.Contains(strings.Join(logs, ""), "Bearer") {
		t.Fatalf("unsanitized %v", logs)
	}
	for i := 0; i < 510; i++ {
		m.addLog("line")
	}
	if len(m.GetLogs()) != 500 {
		t.Fatalf("logs=%d", len(m.GetLogs()))
	}
	for _, tc := range []struct {
		attempt int
		want    time.Duration
	}{{0, 5 * time.Second}, {2, 10 * time.Second}, {20, time.Minute}} {
		if got := reconnectDelay(tc.attempt); got != tc.want {
			t.Errorf("delay %d=%v", tc.attempt, got)
		}
	}
	e := reconnectableVPNError{errors.New("lost")}
	if e.Error() != "lost" || !isReconnectableError(e) {
		t.Fatal("wrapper")
	}
	if classifyOpenConnectExit(errors.New("x"), StateDisconnecting, true, false) != nil {
		t.Fatal("disconnect should succeed")
	}
	if classifyOpenConnectExit(nil, StateConnected, true, false) == nil {
		t.Fatal("established zero exit reconnectable")
	}
	if classifyOpenConnectExit(nil, StateConnecting, false, false) != nil {
		t.Fatal("clean pre-tunnel exit")
	}
	m.mu.Lock()
	m.stopRequested = false
	m.mu.Unlock()
	if !m.waitBeforeReconnect(time.Millisecond) {
		t.Fatal("wait timer")
	}
	m.mu.Lock()
	m.stopRequested = true
	m.mu.Unlock()
	if m.waitBeforeReconnect(time.Second) {
		t.Fatal("cancel")
	}
}

type failAfterWriter struct{ remaining int }

func (w *failAfterWriter) Write(p []byte) (int, error) {
	if w.remaining == 0 {
		return 0, errors.New("write")
	}
	w.remaining--
	return len(p), nil
}

func TestInterfaceSeams(t *testing.T) {
	oldL, oldB, oldA, oldS := listInterfaces, interfaceByName, interfaceAddrs, interfacePollWait
	defer func() { listInterfaces, interfaceByName, interfaceAddrs, interfacePollWait = oldL, oldB, oldA, oldS }()
	listInterfaces = func() ([]net.Interface, error) { return []net.Interface{{Name: "utun42"}}, nil }
	if got := detectTunInterface(); got != "utun42" {
		t.Fatal(got)
	}
	listInterfaces = func() ([]net.Interface, error) { return nil, errors.New("no") }
	interfacePollWait = func(time.Duration) {}
	if got := detectTunInterface(); got != "" {
		t.Fatal(got)
	}
	interfaceByName = func(string) (*net.Interface, error) { return &net.Interface{Name: "x"}, nil }
	interfaceAddrs = func(*net.Interface) ([]net.Addr, error) {
		return []net.Addr{&net.IPNet{IP: net.ParseIP("10.0.0.2"), Mask: net.CIDRMask(24, 32)}, &net.IPAddr{IP: net.ParseIP("10.0.0.3")}}, nil
	}
	if got := getInterfaceIP("x"); got != "10.0.0.2" {
		t.Fatal(got)
	}
	interfaceAddrs = func(*net.Interface) ([]net.Addr, error) {
		return []net.Addr{&net.IPAddr{IP: net.ParseIP("10.0.0.3")}}, nil
	}
	if got := getInterfaceIP("x"); got != "10.0.0.3" {
		t.Fatal(got)
	}
	interfaceByName = func(string) (*net.Interface, error) { return nil, errors.New("missing") }
	if getInterfaceIP("x") != "" {
		t.Fatal("expected empty")
	}
}

func TestFetchServerCertPinLocalTLS(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := tls.X509KeyPair(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}))
	if err != nil {
		t.Fatal(err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, e := ln.Accept()
		if e == nil {
			_, _ = c.Write([]byte("x"))
			_ = c.Close()
		}
	}()
	pin, err := fetchServerCertPin(ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(parsed.RawSubjectPublicKeyInfo)
	want := "pin-sha256:" + base64.StdEncoding.EncodeToString(sum[:])
	if pin != want {
		t.Fatalf("pin=%s want=%s", pin, want)
	}
	if _, err = fetchServerCertPin("127.0.0.1:1"); err == nil {
		t.Fatal("expected dial error")
	}
}

func TestConnectValidationAndStatusIP(t *testing.T) {
	m := NewManager()
	if err := m.Connect(ConnectRequest{AutoReconnect: true}); err == nil {
		t.Fatal("expected validation")
	}
	m.mu.Lock()
	m.state = StateConnecting
	m.mu.Unlock()
	if err := m.Connect(ConnectRequest{}); err == nil {
		t.Fatal("already connecting")
	}
	oldB, oldA := interfaceByName, interfaceAddrs
	defer func() { interfaceByName, interfaceAddrs = oldB, oldA }()
	interfaceByName = func(string) (*net.Interface, error) { return &net.Interface{}, nil }
	interfaceAddrs = func(*net.Interface) ([]net.Addr, error) {
		return []net.Addr{&net.IPNet{IP: net.ParseIP("10.1.2.3"), Mask: net.CIDRMask(24, 32)}}, nil
	}
	m.mu.Lock()
	m.state = StateConnected
	m.connectedAt = time.Now()
	m.tunInterface = "utun1"
	m.otpSecret = "secret"
	m.mu.Unlock()
	s := m.GetStatus()
	if s.IP != "10.1.2.3" || s.Since == "" || !s.AutoOTP {
		t.Fatalf("%+v", s)
	}
}

func TestTOTPValidationErrorsAndBoundaries(t *testing.T) {
	for _, value := range []string{"", "=", "not-base32!", "otpauth://totp/account", "otpauth://%"} {
		if err := ValidateTOTPSecret(value); err == nil {
			t.Errorf("ValidateTOTPSecret(%q) unexpectedly succeeded", value)
		}
	}
	if _, err := generateTOTP("bad!", time.Unix(0, 0)); err == nil {
		t.Fatal("generateTOTP accepted invalid secret")
	}
	if _, wait, err := generateNextTOTP("bad!", 1, time.Unix(30, 0)); err == nil || wait != 0 {
		t.Fatalf("generateNextTOTP error=%v wait=%v", err, wait)
	}
	code, wait, err := generateNextTOTP("JBSWY3DPEHPK3PXP", 1, time.Unix(30, 0))
	if err != nil || code.Step != 2 || wait != 31*time.Second {
		t.Fatalf("boundary code=%+v wait=%v err=%v", code, wait, err)
	}
}

func TestOTPPromptAndSubmitErrorBranches(t *testing.T) {
	m := NewManager()
	m.mu.Lock()
	m.state = StateConnecting
	m.stdin = &bufferWriteCloser{}
	m.otpSecret = "JBSWY3DPEHPK3PXP"
	m.awaitingOTP = true
	m.otpPromptCount = 1
	m.mu.Unlock()
	m.noteOTPPrompt()
	m.mu.Lock()
	m.awaitingOTP = false
	m.autoOTPInFlight = true
	m.mu.Unlock()
	m.noteOTPPrompt()
	m.mu.Lock()
	m.autoOTPInFlight = false
	m.authResponsesSent = 1
	m.mu.Unlock()
	m.noteOTPPrompt()

	m.mu.Lock()
	m.awaitingOTP = true
	m.stdin = nil
	m.mu.Unlock()
	if err := m.SubmitOTP("123456"); err == nil || !strings.Contains(err.Error(), "not available") {
		t.Fatalf("missing stdin error=%v", err)
	}
}

func TestRunConnectLoopStopsReconnect(t *testing.T) {
	old := execCommand
	defer func() { execCommand = old }()
	execCommand = helperCommand("success")
	m := NewManager()
	m.mu.Lock()
	m.state = StateConnecting
	m.stopRequested = true
	m.mu.Unlock()
	err := m.runConnectLoop(ConnectRequest{Portal: "vpn", Password: "pw", OTPSecret: "JBSWY3DPEHPK3PXP", AutoReconnect: true})
	if err != nil {
		t.Fatalf("stopped reconnect returned %v", err)
	}
}
