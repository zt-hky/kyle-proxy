package control

import (
	"errors"
	"reflect"
	"testing"

	"globalprotect-manager/internal/config"
	"globalprotect-manager/internal/vpn"
)

type fakeManager struct {
	connectRequests []vpn.ConnectRequest
	connectErr      error
	submitOTPs      []string
	submitOTPErr    error
	disconnectCalls int
	disconnectErr   error
	status          vpn.Status
	logs            []string
	onEvent         func(vpn.Event)
}

func (m *fakeManager) Connect(req vpn.ConnectRequest) error {
	m.connectRequests = append(m.connectRequests, req)
	return m.connectErr
}

func (m *fakeManager) SubmitOTP(otp string) error {
	m.submitOTPs = append(m.submitOTPs, otp)
	return m.submitOTPErr
}

func (m *fakeManager) Disconnect() error {
	m.disconnectCalls++
	return m.disconnectErr
}

func (m *fakeManager) GetStatus() vpn.Status { return m.status }
func (m *fakeManager) GetLogs() []string     { return m.logs }
func (m *fakeManager) OnEvent(fn func(vpn.Event)) {
	m.onEvent = fn
}

func newTestController(t *testing.T, vpnConfig config.VPNConfig) (*VPN, *fakeManager, *config.AppConfig) {
	t.Helper()

	configManager := config.NewManager(t.TempDir() + "/config.json")
	appConfig := &config.AppConfig{VPN: vpnConfig}
	if err := configManager.Save(appConfig); err != nil {
		t.Fatalf("save test config: %v", err)
	}
	manager := &fakeManager{}
	return &VPN{manager: manager, config: configManager}, manager, appConfig
}

func boolPointer(value bool) *bool { return &value }

func TestConnectRequiresConfiguredPortalAndUsername(t *testing.T) {
	tests := []struct {
		name     string
		portal   string
		username string
	}{
		{name: "both missing"},
		{name: "blank portal", portal: " \t\n", username: "alice"},
		{name: "blank username", portal: "vpn.example.com", username: " \t\n"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			controller, manager, _ := newTestController(t, config.VPNConfig{
				Portal:        tt.portal,
				Username:      tt.username,
				AutoReconnect: true,
			})

			err := controller.Connect(ConnectOptions{})
			if err == nil || err.Error() != "VPN portal and username must be configured first" {
				t.Fatalf("Connect error = %v, want exact portal/username validation error", err)
			}
			if len(manager.connectRequests) != 0 {
				t.Fatal("manager.Connect called after controller validation failed")
			}
		})
	}
}

func TestConnectUsesPersistedAutoReconnectUnlessOverridden(t *testing.T) {
	tests := []struct {
		name              string
		persisted         bool
		override          *bool
		otpSecret         string
		wantAutoReconnect bool
	}{
		{
			name:              "persisted disabled",
			persisted:         false,
			otpSecret:         "",
			wantAutoReconnect: false,
		},
		{
			name:              "persisted enabled",
			persisted:         true,
			otpSecret:         "saved-test-value",
			wantAutoReconnect: true,
		},
		{
			name:              "pointer disables persisted value",
			persisted:         true,
			override:          boolPointer(false),
			otpSecret:         "",
			wantAutoReconnect: false,
		},
		{
			name:              "pointer enables persisted value",
			persisted:         false,
			override:          boolPointer(true),
			otpSecret:         "saved-test-value",
			wantAutoReconnect: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			controller, manager, _ := newTestController(t, config.VPNConfig{
				Portal:        "vpn.example.com",
				Username:      "alice",
				OTPSecret:     tt.otpSecret,
				AutoReconnect: tt.persisted,
			})

			if err := controller.Connect(ConnectOptions{AutoReconnect: tt.override}); err != nil {
				t.Fatalf("Connect returned unexpected error: %v", err)
			}
			if len(manager.connectRequests) != 1 {
				t.Fatalf("manager.Connect call count = %d, want 1", len(manager.connectRequests))
			}
			if manager.connectRequests[0].AutoReconnect != tt.wantAutoReconnect {
				t.Fatal("ConnectRequest.AutoReconnect did not honor persisted value and pointer override")
			}
		})
	}
}

func TestConnectRequiresSavedTOTPWhenAutoReconnectEnabled(t *testing.T) {
	tests := []struct {
		name      string
		persisted bool
		override  *bool
		otpSecret string
	}{
		{
			name:      "persisted auto reconnect",
			persisted: true,
			otpSecret: "",
		},
		{
			name:      "override enables auto reconnect",
			override:  boolPointer(true),
			otpSecret: " \t\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			controller, manager, _ := newTestController(t, config.VPNConfig{
				Portal:        "vpn.example.com",
				Username:      "alice",
				OTPSecret:     tt.otpSecret,
				AutoReconnect: tt.persisted,
			})

			err := controller.Connect(ConnectOptions{AutoReconnect: tt.override})
			if err == nil || err.Error() != "auto reconnect requires a saved OTP secret" {
				t.Fatalf("Connect error = %v, want exact saved-TOTP validation error", err)
			}
			if len(manager.connectRequests) != 0 {
				t.Fatal("manager.Connect called after saved-TOTP validation failed")
			}
		})
	}
}

func TestConnectCopiesEveryRequestFieldAndIsolatesExtraArgs(t *testing.T) {
	vpnConfig := config.VPNConfig{
		Portal:        "vpn.example.com",
		Gateway:       "gateway.example.com",
		Username:      "alice",
		Password:      "password-test-value",
		OTPSecret:     "saved-test-value",
		AutoReconnect: false,
		CertFile:      "/data/custom-ca.pem",
		TrustCert:     true,
		ExtraArgs:     []string{"--protocol=gp", "--usergroup=employees"},
	}
	controller, manager, storedConfig := newTestController(t, vpnConfig)
	options := ConnectOptions{
		OTP:           "initial-test-value",
		OTP2:          "followup-test-value",
		AutoReconnect: boolPointer(true),
	}

	if err := controller.Connect(options); err != nil {
		t.Fatalf("Connect returned unexpected error: %v", err)
	}
	if len(manager.connectRequests) != 1 {
		t.Fatalf("manager.Connect call count = %d, want 1", len(manager.connectRequests))
	}
	req := manager.connectRequests[0]
	if req.Portal != vpnConfig.Portal {
		t.Fatal("ConnectRequest.Portal was not copied")
	}
	if req.Gateway != vpnConfig.Gateway {
		t.Fatal("ConnectRequest.Gateway was not copied")
	}
	if req.Username != vpnConfig.Username {
		t.Fatal("ConnectRequest.Username was not copied")
	}
	if req.Password != vpnConfig.Password {
		t.Fatal("ConnectRequest.Password was not copied")
	}
	if req.OTP != options.OTP {
		t.Fatal("ConnectRequest.OTP was not copied")
	}
	if req.OTP2 != options.OTP2 {
		t.Fatal("ConnectRequest.OTP2 was not copied")
	}
	if req.OTPSecret != vpnConfig.OTPSecret {
		t.Fatal("ConnectRequest.OTPSecret was not copied")
	}
	if !req.AutoReconnect {
		t.Fatal("ConnectRequest.AutoReconnect was not copied")
	}
	if req.CertFile != vpnConfig.CertFile {
		t.Fatal("ConnectRequest.CertFile was not copied")
	}
	if req.TrustCert != vpnConfig.TrustCert {
		t.Fatal("ConnectRequest.TrustCert was not copied")
	}
	if !reflect.DeepEqual(req.ExtraArgs, vpnConfig.ExtraArgs) {
		t.Fatal("ConnectRequest.ExtraArgs was not copied")
	}

	storedConfig.VPN.ExtraArgs[0] = "--changed-in-config"
	if manager.connectRequests[0].ExtraArgs[0] != "--protocol=gp" {
		t.Fatal("ConnectRequest.ExtraArgs aliases config storage")
	}
	manager.connectRequests[0].ExtraArgs[1] = "--changed-in-request"
	if storedConfig.VPN.ExtraArgs[1] != "--usergroup=employees" {
		t.Fatal("config ExtraArgs aliases ConnectRequest storage")
	}
}

func TestConnectReturnsManagerError(t *testing.T) {
	controller, manager, _ := newTestController(t, config.VPNConfig{
		Portal:   "vpn.example.com",
		Username: "alice",
	})
	wantErr := errors.New("connect rejected")
	manager.connectErr = wantErr

	if err := controller.Connect(ConnectOptions{}); !errors.Is(err, wantErr) {
		t.Fatalf("Connect error = %v, want manager error", err)
	}
	if len(manager.connectRequests) != 1 {
		t.Fatalf("manager.Connect call count = %d, want 1", len(manager.connectRequests))
	}
}

func TestControllerDelegatesManagerOperations(t *testing.T) {
	controller, manager, _ := newTestController(t, config.VPNConfig{})
	submitErr := errors.New("submit rejected")
	disconnectErr := errors.New("disconnect rejected")
	manager.submitOTPErr = submitErr
	manager.disconnectErr = disconnectErr
	manager.status = vpn.Status{
		State:            vpn.StateConnecting,
		Phase:            "gateway-login",
		Detail:           "Waiting for challenge",
		LastLog:          "Login started",
		IP:               "192.0.2.10",
		Interface:        "utun8",
		Error:            "temporary failure",
		Since:            "2026-07-19T12:00:00Z",
		AwaitingOTP:      true,
		OTPPromptCount:   2,
		AutoOTP:          true,
		AutoReconnect:    true,
		ReconnectAttempt: 3,
	}
	manager.logs = []string{"first", "second"}

	if err := controller.SubmitOTP("test-otp-value"); !errors.Is(err, submitErr) {
		t.Fatalf("SubmitOTP error = %v, want manager error", err)
	}
	if len(manager.submitOTPs) != 1 || manager.submitOTPs[0] != "test-otp-value" {
		t.Fatal("SubmitOTP argument was not delegated unchanged")
	}
	if err := controller.Disconnect(); !errors.Is(err, disconnectErr) {
		t.Fatalf("Disconnect error = %v, want manager error", err)
	}
	if manager.disconnectCalls != 1 {
		t.Fatalf("manager.Disconnect call count = %d, want 1", manager.disconnectCalls)
	}
	if got := controller.Status(); !reflect.DeepEqual(got, manager.status) {
		t.Fatal("Status did not return the manager status")
	}
	if got := controller.Logs(); !reflect.DeepEqual(got, manager.logs) {
		t.Fatal("Logs did not return the manager logs")
	}

	var received vpn.Event
	controller.OnEvent(func(event vpn.Event) { received = event })
	if manager.onEvent == nil {
		t.Fatal("OnEvent callback was not registered with the manager")
	}
	wantEvent := vpn.Event{
		ID:      42,
		Kind:    vpn.EventKindPhase,
		Name:    "gateway-login",
		Outcome: "accepted",
		Status:  manager.status,
		Detail:  "challenge requested",
	}
	manager.onEvent(wantEvent)
	if !reflect.DeepEqual(received, wantEvent) {
		t.Fatal("OnEvent callback did not receive the manager event unchanged")
	}
}

func TestHasSavedOTPTrimsWhitespace(t *testing.T) {
	tests := []struct {
		name   string
		secret string
		want   bool
	}{
		{name: "missing"},
		{name: "whitespace", secret: " \t\n"},
		{name: "saved", secret: " saved-test-value ", want: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			controller, _, _ := newTestController(t, config.VPNConfig{OTPSecret: tt.secret})
			if got := controller.HasSavedOTP(); got != tt.want {
				t.Fatalf("HasSavedOTP() = %v, want %v", got, tt.want)
			}
		})
	}
}
