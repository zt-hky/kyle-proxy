package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"globalprotect-manager/internal/auth"
	"globalprotect-manager/internal/config"
	"globalprotect-manager/internal/control"
	"globalprotect-manager/internal/vpn"
)

// Handler holds all dependencies for HTTP handlers
type Handler struct {
	controller *control.VPN
	cfgMgr     *config.Manager
	githubAuth *auth.GitHubAuth
}

func newHandler(cn *control.VPN, c *config.Manager, ga *auth.GitHubAuth) *Handler {
	return &Handler{controller: cn, cfgMgr: c, githubAuth: ga}
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

func readJSON(r *http.Request, v any) error {
	return json.NewDecoder(r.Body).Decode(v)
}

func (h *Handler) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "time": time.Now().Format(time.RFC3339)})
}

type statusResponse struct {
	VPN vpn.Status `json:"vpn"`
}

func (h *Handler) handleStatus(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, statusResponse{VPN: h.controller.Status()})
}

type configResponse struct {
	Portal        string   `json:"portal"`
	Gateway       string   `json:"gateway"`
	Username      string   `json:"username"`
	HasPass       bool     `json:"has_password"`
	HasOTPSecret  bool     `json:"has_otp_secret"`
	AutoReconnect bool     `json:"auto_reconnect"`
	CertFile      string   `json:"cert_file"`
	TrustCert     bool     `json:"trust_cert"`
	ExtraArgs     []string `json:"extra_args"`
}

func (h *Handler) handleGetConfig(w http.ResponseWriter, _ *http.Request) {
	cfg := h.cfgMgr.Get()
	writeJSON(w, http.StatusOK, configResponse{
		Portal: cfg.VPN.Portal, Gateway: cfg.VPN.Gateway, Username: cfg.VPN.Username,
		HasPass: cfg.VPN.Password != "", HasOTPSecret: cfg.VPN.OTPSecret != "",
		AutoReconnect: cfg.VPN.AutoReconnect && cfg.VPN.OTPSecret != "",
		CertFile:      cfg.VPN.CertFile, TrustCert: cfg.VPN.TrustCert, ExtraArgs: cfg.VPN.ExtraArgs,
	})
}

type updateConfigRequest struct {
	Portal         string   `json:"portal"`
	Gateway        string   `json:"gateway"`
	Username       string   `json:"username"`
	Password       string   `json:"password"`
	OTPSecret      string   `json:"otp_secret"`
	ClearOTPSecret bool     `json:"clear_otp_secret"`
	AutoReconnect  bool     `json:"auto_reconnect"`
	CertFile       string   `json:"cert_file"`
	TrustCert      bool     `json:"trust_cert"`
	ExtraArgs      []string `json:"extra_args"`
}

func (h *Handler) handleUpdateConfig(w http.ResponseWriter, r *http.Request) {
	var req updateConfigRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	cfg := h.cfgMgr.Get()
	cfg.VPN.Portal, cfg.VPN.Gateway, cfg.VPN.Username = req.Portal, req.Gateway, req.Username
	cfg.VPN.CertFile, cfg.VPN.TrustCert = req.CertFile, req.TrustCert
	if req.ExtraArgs != nil {
		cfg.VPN.ExtraArgs = req.ExtraArgs
	}
	if req.Password != "" {
		cfg.VPN.Password = req.Password
	}
	if req.ClearOTPSecret {
		cfg.VPN.OTPSecret = ""
	} else if secret := strings.TrimSpace(req.OTPSecret); secret != "" {
		if err := vpn.ValidateTOTPSecret(secret); err != nil {
			writeError(w, http.StatusBadRequest, "invalid OTP secret: "+err.Error())
			return
		}
		cfg.VPN.OTPSecret = secret
	}
	cfg.VPN.AutoReconnect = req.AutoReconnect && cfg.VPN.OTPSecret != ""
	if err := h.cfgMgr.Save(cfg); err != nil {
		writeError(w, http.StatusInternalServerError, "save config: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "saved"})
}

type connectRequest struct {
	OTP           string `json:"otp"`
	OTP2          string `json:"otp2"`
	AutoReconnect *bool  `json:"auto_reconnect"`
}

func (h *Handler) handleConnect(w http.ResponseWriter, r *http.Request) {
	var req connectRequest
	_ = readJSON(r, &req)
	if err := h.controller.Connect(control.ConnectOptions{OTP: req.OTP, OTP2: req.OTP2, AutoReconnect: req.AutoReconnect}); err != nil {
		if strings.Contains(err.Error(), "configured first") || strings.Contains(err.Error(), "saved OTP") {
			writeError(w, http.StatusBadRequest, err.Error())
		} else {
			writeError(w, http.StatusConflict, err.Error())
		}
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]string{"status": "connecting"})
}

type otpRequest struct {
	OTP string `json:"otp"`
}

func (h *Handler) handleVPNOTP(w http.ResponseWriter, r *http.Request) {
	var req otpRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	if err := h.controller.SubmitOTP(req.OTP); err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]string{"status": "submitted"})
}

func (h *Handler) handleDisconnect(w http.ResponseWriter, _ *http.Request) {
	if err := h.controller.Disconnect(); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "disconnecting"})
}

func (h *Handler) handleLogs(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string][]string{"lines": h.controller.Logs()})
}

func (h *Handler) handleCertUpload(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseMultipartForm(1 << 20); err != nil {
		writeError(w, http.StatusBadRequest, "parse form: "+err.Error())
		return
	}
	file, _, err := r.FormFile("cert")
	if err != nil {
		writeError(w, http.StatusBadRequest, "cert file required (field: cert)")
		return
	}
	defer file.Close()
	certDir := "/data/certs"
	if err := os.MkdirAll(certDir, 0755); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	certPath := certDir + "/custom-ca.crt"
	out, err := os.Create(certPath)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	defer out.Close()
	buf := make([]byte, 4096)
	for {
		n, rErr := file.Read(buf)
		if n > 0 {
			if _, wErr := out.Write(buf[:n]); wErr != nil {
				writeError(w, http.StatusInternalServerError, wErr.Error())
				return
			}
		}
		if rErr != nil {
			break
		}
	}
	cfg := h.cfgMgr.Get()
	cfg.VPN.CertFile = certPath
	_ = h.cfgMgr.Save(cfg)
	installCmd := exec.Command("sh", "-c",
		fmt.Sprintf("cp %s /usr/local/share/ca-certificates/globalprotect-manager-ca.crt && update-ca-certificates", certPath))
	if outBytes, err := installCmd.CombinedOutput(); err != nil {
		writeJSON(w, http.StatusOK, map[string]string{
			"status": "uploaded", "path": certPath,
			"warning": fmt.Sprintf("system trust install failed: %s", string(outBytes)),
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "uploaded", "path": certPath})
}
