package api

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"time"

	"kyle-proxy/internal/auth"
	"kyle-proxy/internal/config"
	"kyle-proxy/internal/proxy"
	"kyle-proxy/internal/users"
	"kyle-proxy/internal/vpn"
)

// Handler holds all dependencies for HTTP handlers
type Handler struct {
	vpnMgr     *vpn.Manager
	proxyMgr   *proxy.Manager
	cfgMgr     *config.Manager
	userStore  *users.Store
	githubAuth *auth.GitHubAuth
}

func newHandler(v *vpn.Manager, p *proxy.Manager, c *config.Manager, us *users.Store, ga *auth.GitHubAuth) *Handler {
	return &Handler{vpnMgr: v, proxyMgr: p, cfgMgr: c, userStore: us, githubAuth: ga}
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
	VPN   vpn.Status       `json:"vpn"`
	Proxy proxyStatusExt   `json:"proxy"`
}

func (h *Handler) handleStatus(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, statusResponse{
		VPN:   h.vpnMgr.GetStatus(),
		Proxy: toStatusExt(h.proxyMgr.GetStatus(), h.proxyMgr.GetVMessPort()),
	})
}

type configResponse struct {
	Portal     string   `json:"portal"`
	Gateway    string   `json:"gateway"`
	Username   string   `json:"username"`
	HasPass    bool     `json:"has_password"`
	CertFile   string   `json:"cert_file"`
	TrustCert  bool     `json:"trust_cert"`
	ExtraArgs  []string `json:"extra_args"`
	HTTPPort   int      `json:"http_port"`
	Socks5Port int      `json:"socks5_port"`
	VMessPort  int      `json:"vmess_port"`
	ServerHost string   `json:"server_host"`
}

func (h *Handler) handleGetConfig(w http.ResponseWriter, _ *http.Request) {
	cfg := h.cfgMgr.Get()
	writeJSON(w, http.StatusOK, configResponse{
		Portal: cfg.VPN.Portal, Gateway: cfg.VPN.Gateway, Username: cfg.VPN.Username,
		HasPass: cfg.VPN.Password != "", CertFile: cfg.VPN.CertFile, TrustCert: cfg.VPN.TrustCert,
		ExtraArgs: cfg.VPN.ExtraArgs, HTTPPort: cfg.Proxy.HTTPPort, Socks5Port: cfg.Proxy.Socks5Port,
		VMessPort: cfg.Proxy.VMessPort, ServerHost: cfg.Proxy.ServerHost,
	})
}

type updateConfigRequest struct {
	Portal     string   `json:"portal"`
	Gateway    string   `json:"gateway"`
	Username   string   `json:"username"`
	Password   string   `json:"password"`
	CertFile   string   `json:"cert_file"`
	TrustCert  bool     `json:"trust_cert"`
	ExtraArgs  []string `json:"extra_args"`
	HTTPPort   int      `json:"http_port"`
	Socks5Port int      `json:"socks5_port"`
	VMessPort  int      `json:"vmess_port"`
	ServerHost string   `json:"server_host"`
}

func (h *Handler) handleUpdateConfig(w http.ResponseWriter, r *http.Request) {
	var req updateConfigRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	cfg := h.cfgMgr.Get()
	cfg.VPN.Portal = req.Portal
	cfg.VPN.Gateway = req.Gateway
	cfg.VPN.Username = req.Username
	cfg.VPN.CertFile = req.CertFile
	cfg.VPN.TrustCert = req.TrustCert
	if req.ExtraArgs != nil {
		cfg.VPN.ExtraArgs = req.ExtraArgs
	}
	if req.Password != "" {
		cfg.VPN.Password = req.Password
	}
	if req.HTTPPort > 0 {
		cfg.Proxy.HTTPPort = req.HTTPPort
	}
	if req.Socks5Port > 0 {
		cfg.Proxy.Socks5Port = req.Socks5Port
	}
	if req.VMessPort > 0 {
		cfg.Proxy.VMessPort = req.VMessPort
	}
	cfg.Proxy.ServerHost = req.ServerHost // allow setting or clearing
	if err := h.cfgMgr.Save(cfg); err != nil {
		writeError(w, http.StatusInternalServerError, "save config: "+err.Error())
		return
	}
	if req.HTTPPort > 0 || req.Socks5Port > 0 || req.VMessPort > 0 {
		go func() {
			_ = h.proxyMgr.UpdateConfig(proxy.Config{
				HTTPPort: cfg.Proxy.HTTPPort, Socks5Port: cfg.Proxy.Socks5Port, VMessPort: cfg.Proxy.VMessPort,
			})
		}()
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "saved"})
}

type connectRequest struct {
	OTP string `json:"otp"`
}

func (h *Handler) handleConnect(w http.ResponseWriter, r *http.Request) {
	var req connectRequest
	_ = readJSON(r, &req)
	cfg := h.cfgMgr.Get()
	if cfg.VPN.Portal == "" || cfg.VPN.Username == "" {
		writeError(w, http.StatusBadRequest, "VPN portal and username must be configured first")
		return
	}
	if err := h.vpnMgr.Connect(vpn.ConnectRequest{
		Portal: cfg.VPN.Portal, Gateway: cfg.VPN.Gateway, Username: cfg.VPN.Username,
		Password: cfg.VPN.Password, OTP: req.OTP, CertFile: cfg.VPN.CertFile,
		TrustCert: cfg.VPN.TrustCert,
	}); err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]string{"status": "connecting"})
}

func (h *Handler) handleDisconnect(w http.ResponseWriter, _ *http.Request) {
	if err := h.vpnMgr.Disconnect(); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "disconnecting"})
}

func (h *Handler) handleLogs(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string][]string{"lines": h.vpnMgr.GetLogs()})
}


func (h *Handler) handleProxyInfo(w http.ResponseWriter, r *http.Request) {
	cfg := h.cfgMgr.Get()
	host := getOutboundIP()
	if rh, _, err := net.SplitHostPort(r.Host); err == nil && rh != "" {
		host = rh
	}
	if sh := cfg.Proxy.ServerHost; sh != "" {
		host = sh // user-configured public host takes priority
	}
	vMessPort := h.proxyMgr.GetVMessPort()
	hasUsers := len(h.userStore.ListUsers()) > 0
	writeJSON(w, http.StatusOK, proxyInfoExtended{
		HostIP: host, HTTPPort: cfg.Proxy.HTTPPort, Socks5Port: cfg.Proxy.Socks5Port,
		VMessPort:  vMessPort,
		HTTPProxy:  fmt.Sprintf("http://%s:%d", host, cfg.Proxy.HTTPPort),
		Socks5:     fmt.Sprintf("socks5://%s:%d", host, cfg.Proxy.Socks5Port),
		PACUrl:     fmt.Sprintf("http://%s:8888/pac", host),
		AuthMode:   hasUsers,
	})
}

// GET /pac — Proxy Auto-Config for iPhone:
// Settings → Wi-Fi → ⓘ → Configure Proxy → Auto → URL: http://\<host\>:8888/pac
func (h *Handler) handlePAC(w http.ResponseWriter, _ *http.Request) {
	cfg := h.cfgMgr.Get()
	host := getOutboundIP()
	pac := fmt.Sprintf(`function FindProxyForURL(url, host) {
    if (isInNet(dnsResolve(host),"10.0.0.0","255.0.0.0") ||
        isInNet(dnsResolve(host),"172.16.0.0","255.240.0.0") ||
        isInNet(dnsResolve(host),"192.168.0.0","255.255.0.0") ||
        isInNet(dnsResolve(host),"127.0.0.0","255.0.0.0") ||
        isPlainHostName(host)) { return "DIRECT"; }
    return "PROXY %s:%d";
}
`, host, cfg.Proxy.HTTPPort)
	w.Header().Set("Content-Type", "application/x-ns-proxy-autoconfig")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(pac))
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
fmt.Sprintf("cp %s /usr/local/share/ca-certificates/kyle-proxy-ca.crt && update-ca-certificates", certPath))
	if outBytes, err := installCmd.CombinedOutput(); err != nil {
		writeJSON(w, http.StatusOK, map[string]string{
"status": "uploaded", "path": certPath,
"warning": fmt.Sprintf("system trust install failed: %s", string(outBytes)),
})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "uploaded", "path": certPath})
}

func getOutboundIP() string {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return "127.0.0.1"
	}
	defer conn.Close()
	return conn.LocalAddr().(*net.UDPAddr).IP.String()
}
