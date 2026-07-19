package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"globalprotect-manager/internal/auth"
	"globalprotect-manager/internal/config"
	"globalprotect-manager/internal/control"
	"globalprotect-manager/internal/vpn"
)

type fakeController struct {
	status        vpn.Status
	logs          []string
	connectErr    error
	otpErr        error
	disconnectErr error
	connect       control.ConnectOptions
	otp           string
}

func (f *fakeController) Connect(o control.ConnectOptions) error { f.connect = o; return f.connectErr }
func (f *fakeController) SubmitOTP(s string) error               { f.otp = s; return f.otpErr }
func (f *fakeController) Disconnect() error                      { return f.disconnectErr }
func (f *fakeController) Status() vpn.Status                     { return f.status }
func (f *fakeController) Logs() []string                         { return f.logs }

func testHandler(t *testing.T, f *fakeController) (*Handler, *config.Manager) {
	t.Helper()
	m := config.NewManager(filepath.Join(t.TempDir(), "config.json"))
	m.Load()
	return newHandler(f, m, auth.NewGitHubAuth()), m
}

func call(fn http.HandlerFunc, method, target, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, target, strings.NewReader(body))
	w := httptest.NewRecorder()
	fn(w, r)
	return w
}

func TestHealthStatusConfigAndLogs(t *testing.T) {
	f := &fakeController{status: vpn.Status{State: vpn.StateConnected}, logs: []string{"one", "two"}}
	h, m := testHandler(t, f)
	cfg := m.Get()
	cfg.VPN.Portal, cfg.VPN.Gateway, cfg.VPN.Username = "portal", "gateway", "alice"
	cfg.VPN.Password, cfg.VPN.OTPSecret, cfg.VPN.AutoReconnect = "secret", "JBSWY3DPEHPK3PXP", true
	cfg.VPN.CertFile, cfg.VPN.TrustCert, cfg.VPN.ExtraArgs = "cert", true, []string{"--foo"}
	if err := m.Save(cfg); err != nil {
		t.Fatal(err)
	}
	for name, fn := range map[string]http.HandlerFunc{"health": h.handleHealth, "status": h.handleStatus, "config": h.handleGetConfig, "logs": h.handleLogs} {
		w := call(fn, http.MethodGet, "/", "")
		if w.Code != http.StatusOK || !strings.Contains(w.Header().Get("Content-Type"), "application/json") {
			t.Fatalf("%s: %d %s", name, w.Code, w.Body.String())
		}
	}
	w := call(h.handleGetConfig, http.MethodGet, "/", "")
	for _, want := range []string{`"portal":"portal"`, `"has_password":true`, `"has_otp_secret":true`, `"auto_reconnect":true`, `"cert_file":"cert"`, `"trust_cert":true`, `"extra_args":["--foo"]`} {
		if !strings.Contains(w.Body.String(), want) {
			t.Errorf("config missing %s: %s", want, w.Body.String())
		}
	}
}

func TestUpdateConfigPaths(t *testing.T) {
	h, m := testHandler(t, &fakeController{})
	if w := call(h.handleUpdateConfig, http.MethodPut, "/", "{"); w.Code != http.StatusBadRequest {
		t.Fatalf("malformed = %d", w.Code)
	}
	body := `{"portal":"p","gateway":"g","username":"u","password":"pw","otp_secret":"JBSWY3DPEHPK3PXP","auto_reconnect":true,"cert_file":"c","trust_cert":true,"extra_args":["x"]}`
	if w := call(h.handleUpdateConfig, http.MethodPut, "/", body); w.Code != http.StatusOK {
		t.Fatalf("update = %d %s", w.Code, w.Body.String())
	}
	cfg := m.Get()
	if cfg.VPN.Password != "pw" || cfg.VPN.OTPSecret == "" || !cfg.VPN.AutoReconnect || len(cfg.VPN.ExtraArgs) != 1 {
		t.Fatalf("saved config = %+v", cfg.VPN)
	}
	if w := call(h.handleUpdateConfig, http.MethodPut, "/", `{"clear_otp_secret":true,"auto_reconnect":true}`); w.Code != http.StatusOK {
		t.Fatal(w.Body.String())
	}
	if cfg = m.Get(); cfg.VPN.OTPSecret != "" || cfg.VPN.AutoReconnect {
		t.Fatalf("cleared config = %+v", cfg.VPN)
	}
	if w := call(h.handleUpdateConfig, http.MethodPut, "/", `{"otp_secret":"%%%"}`); w.Code != http.StatusBadRequest {
		t.Fatalf("invalid secret = %d", w.Code)
	}

	badParent := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(badParent, []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	bad := config.NewManager(filepath.Join(badParent, "config.json"))
	bad.Load()
	badHandler := newHandler(&fakeController{}, bad, auth.NewGitHubAuth())
	if w := call(badHandler.handleUpdateConfig, http.MethodPut, "/", `{}`); w.Code != http.StatusInternalServerError {
		t.Fatalf("save error = %d %s", w.Code, w.Body.String())
	}
}

func TestConnectOTPDisconnectPaths(t *testing.T) {
	f := &fakeController{}
	h, _ := testHandler(t, f)
	auto := false
	_ = auto
	if w := call(h.handleConnect, http.MethodPost, "/", `{"otp":"1","otp2":"2","auto_reconnect":false}`); w.Code != http.StatusAccepted || f.connect.OTP != "1" || f.connect.AutoReconnect == nil || *f.connect.AutoReconnect {
		t.Fatalf("connect = %d %+v", w.Code, f.connect)
	}
	for _, tt := range []struct {
		err  error
		code int
	}{{errors.New("must be configured first"), 400}, {errors.New("requires a saved OTP"), 400}, {errors.New("already connected"), 409}} {
		f.connectErr = tt.err
		if w := call(h.handleConnect, http.MethodPost, "/", "{"); w.Code != tt.code {
			t.Fatalf("connect error %v = %d", tt.err, w.Code)
		}
	}
	f.connectErr = nil
	if w := call(h.handleVPNOTP, http.MethodPost, "/", "{"); w.Code != http.StatusBadRequest {
		t.Fatalf("bad otp json = %d", w.Code)
	}
	if w := call(h.handleVPNOTP, http.MethodPost, "/", `{"otp":"123"}`); w.Code != http.StatusAccepted || f.otp != "123" {
		t.Fatalf("otp = %d %q", w.Code, f.otp)
	}
	f.otpErr = errors.New("not waiting")
	if w := call(h.handleVPNOTP, http.MethodPost, "/", `{"otp":"123"}`); w.Code != http.StatusConflict {
		t.Fatalf("otp conflict = %d", w.Code)
	}
	if w := call(h.handleDisconnect, http.MethodPost, "/", ""); w.Code != http.StatusOK {
		t.Fatalf("disconnect = %d", w.Code)
	}
	f.disconnectErr = errors.New("stop failed")
	if w := call(h.handleDisconnect, http.MethodPost, "/", ""); w.Code != http.StatusInternalServerError {
		t.Fatalf("disconnect error = %d", w.Code)
	}
}

func multipartRequest(t *testing.T, withFile bool) *http.Request {
	t.Helper()
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	if withFile {
		part, err := mw.CreateFormFile("cert", "ca.crt")
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.WriteString(part, "certificate")
	}
	if err := mw.Close(); err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodPost, "/", &body)
	r.Header.Set("Content-Type", mw.FormDataContentType())
	return r
}

func TestCertUploadPaths(t *testing.T) {
	h, m := testHandler(t, &fakeController{})
	if w := call(h.handleCertUpload, http.MethodPost, "/", "not multipart"); w.Code != http.StatusBadRequest {
		t.Fatalf("parse = %d", w.Code)
	}
	r := multipartRequest(t, false)
	w := httptest.NewRecorder()
	h.handleCertUpload(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("missing file = %d", w.Code)
	}
	oldDir, oldInstall := certDirectory, installCertificate
	t.Cleanup(func() { certDirectory, installCertificate = oldDir, oldInstall })
	certDirectory = filepath.Join(t.TempDir(), "certs")
	installCertificate = func(string) ([]byte, error) { return []byte("denied"), errors.New("failed") }
	r = multipartRequest(t, true)
	w = httptest.NewRecorder()
	h.handleCertUpload(w, r)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "warning") {
		t.Fatalf("warning = %d %s", w.Code, w.Body.String())
	}
	if got := m.Get().VPN.CertFile; got != filepath.Join(certDirectory, "custom-ca.crt") {
		t.Fatalf("cert path = %q", got)
	}
	installCertificate = func(string) ([]byte, error) { return nil, nil }
	r = multipartRequest(t, true)
	w = httptest.NewRecorder()
	h.handleCertUpload(w, r)
	if w.Code != http.StatusOK || strings.Contains(w.Body.String(), "warning") {
		t.Fatalf("success = %d %s", w.Code, w.Body.String())
	}
}

func TestJSONHelpers(t *testing.T) {
	var v map[string]int
	r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"n":2}`))
	if err := readJSON(r, &v); err != nil || v["n"] != 2 {
		t.Fatalf("readJSON = %v %v", v, err)
	}
	w := httptest.NewRecorder()
	writeError(w, 418, "teapot")
	var got map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil || got["error"] != "teapot" {
		t.Fatalf("writeError = %v %v", got, err)
	}
}
