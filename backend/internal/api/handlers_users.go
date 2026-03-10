package api

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"kyle-proxy/internal/auth"
	"kyle-proxy/internal/proxy"
	"kyle-proxy/internal/users"
)

// ─── User handlers ────────────────────────────────────────────────────────────

func (h *Handler) handleListUsers(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"users": h.userStore.ListUsers()})
}

type createUserRequest struct {
	Username string   `json:"username"`
	Password string   `json:"password"`
	Groups   []string `json:"groups"`
	Note     string   `json:"note"`
}

func (h *Handler) handleCreateUser(w http.ResponseWriter, r *http.Request) {
	var req createUserRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if strings.TrimSpace(req.Username) == "" {
		writeError(w, http.StatusBadRequest, "username is required")
		return
	}
	u, err := h.userStore.CreateUser(req.Username, req.Password, req.Groups, req.Note)
	if err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	h.reloadProxy()
	writeJSON(w, http.StatusCreated, u)
}

type updateUserRequest struct {
	Password    string   `json:"password"`
	Groups      []string `json:"groups"`
	Enabled     bool     `json:"enabled"`
	Note        string   `json:"note"`
	RegenToken  bool     `json:"regen_token"`
}

func (h *Handler) handleUpdateUser(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	var req updateUserRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	u, err := h.userStore.UpdateUser(id, req.Password, req.Groups, req.Enabled, req.Note, req.RegenToken)
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	h.reloadProxy()
	writeJSON(w, http.StatusOK, u)
}

func (h *Handler) handleDeleteUser(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if err := h.userStore.DeleteUser(id); err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	h.reloadProxy()
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

// ─── Group handlers ────────────────────────────────────────────────────────────

func (h *Handler) handleListGroups(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"groups": h.userStore.ListGroups()})
}

type createGroupRequest struct {
	Name        string   `json:"name"`
	Patterns    []string `json:"allowed_patterns"`
	Description string   `json:"description"`
}

func (h *Handler) handleCreateGroup(w http.ResponseWriter, r *http.Request) {
	var req createGroupRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if strings.TrimSpace(req.Name) == "" {
		writeError(w, http.StatusBadRequest, "name is required")
		return
	}
	g, err := h.userStore.CreateGroup(req.Name, req.Patterns, req.Description)
	if err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	h.reloadProxy()
	writeJSON(w, http.StatusCreated, g)
}

func (h *Handler) handleUpdateGroup(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	var req createGroupRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	g, err := h.userStore.UpdateGroup(id, req.Name, req.Patterns, req.Description)
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	h.reloadProxy()
	writeJSON(w, http.StatusOK, g)
}

func (h *Handler) handleDeleteGroup(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if err := h.userStore.DeleteGroup(id); err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	h.reloadProxy()
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

// ─── VMess export ─────────────────────────────────────────────────────────────

// handleVMessExport returns a vmess:// link for a user, for import in v2box / v2ray clients.
// GET /api/users/{id}/vmess?host=<server-host>
func (h *Handler) handleVMessExport(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	u, err := h.userStore.GetUser(id)
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}

	host := r.URL.Query().Get("host")
	if host == "" {
		host = h.cfgMgr.Get().Proxy.ServerHost
	}
	if host == "" {
		host = getOutboundIP()
	}
	port := h.proxyMgr.GetVMessPort()

	link := buildVMessLink(u.VMessUUID, u.Username, host, port)
	writeJSON(w, http.StatusOK, map[string]any{
		"vmess_link": link,
		"host":       host,
		"port":       port,
		"uuid":       u.VMessUUID,
		"username":   u.Username,
		"note":       fmt.Sprintf("Import in v2box/v2ray: Settings → Add Server → Scan QR or paste vmess:// link"),
	})
}

// handleV2RayClientConfig returns a complete v2ray client JSON config for
// import in v2rayNG / v2box / v2rayN.  The response is served with a
// Content-Disposition: attachment header so navigating to the URL directly
// also triggers a browser download.
//
// The config includes:
//   - SOCKS5 inbound on 127.0.0.1:1080 (local)
//   - HTTP  inbound on 127.0.0.1:8080 (local)
//   - VMess outbound pointing at this server with the user's UUID
//   - Routing rules that implement split-tunnel (only group-pattern domains
//     are sent through the proxy; everything else is DIRECT).
//
// GET /api/users/{id}/v2ray-config?host=<override-host>
func (h *Handler) handleV2RayClientConfig(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	u, err := h.userStore.GetUser(id)
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	cfg := h.cfgMgr.Get()
	host := r.URL.Query().Get("host")
	if host == "" {
		host = cfg.Proxy.ServerHost
	}
	if host == "" {
		host = getOutboundIP()
	}
	port := h.proxyMgr.GetVMessPort()
	patterns := h.userStore.GetUserPatterns(u.Username)

	clientCfg := proxy.BuildClientConfig(u.VMessUUID, u.Username, host, port, patterns)
	b, err := proxy.MarshalClientConfig(clientCfg)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "marshal config: "+err.Error())
		return
	}

	filename := "v2ray-" + u.Username + ".json"
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Content-Disposition", "attachment; filename=\""+filename+"\"")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(b)
}

// buildVMessLink creates the standard vmess:// URI for v2ray/v2box clients.
func buildVMessLink(uuid, name, host string, port int) string {
	payload := map[string]any{
		"v":    "2",
		"ps":   "Kyle-Proxy/" + name,
		"add":  host,
		"port": fmt.Sprintf("%d", port),
		"id":   uuid,
		"aid":  "0",
		"scy":  "auto",
		"net":  "tcp",
		"type": "none",
		"host": "",
		"path": "",
		"tls":  "",
		"sni":  "",
		"alpn": "",
		"fp":   "",
	}
	b, _ := json.Marshal(payload)
	return "vmess://" + base64.StdEncoding.EncodeToString(b)
}

// ─── Per-user PAC ─────────────────────────────────────────────────────────────

// handleUserPAC generates a PAC file for a specific user's allowed patterns.
// GET /pac/{username}  — public endpoint (no auth), proxy auth is handled by the device.
func (h *Handler) handleUserPAC(w http.ResponseWriter, r *http.Request) {
	username := chi.URLParam(r, "username")
	cfg := h.cfgMgr.Get()

	host := getOutboundIP()
	if rh, _, err := splitHost(r.Host); err == nil && rh != "" {
		host = rh
	}

	patterns := h.userStore.GetUserPatterns(username)
	pac := buildPAC(host, cfg.Proxy.HTTPPort, username, patterns)

	w.Header().Set("Content-Type", "application/x-ns-proxy-autoconfig")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(pac))
}

// buildPAC generates a PAC file. If patterns is nil, all traffic goes through proxy.
// If patterns is non-empty, only matching hosts go through proxy; rest is DIRECT.
func buildPAC(host string, port int, username string, patterns []string) string {
	proxyAddr := fmt.Sprintf("PROXY %s:%d", host, port)

	if len(patterns) == 0 {
		// No restriction: route everything through proxy (except private IPs)
		return fmt.Sprintf(`// PAC for user: %s — all traffic via proxy
function FindProxyForURL(url, host) {
    if (isInNet(dnsResolve(host),"10.0.0.0","255.0.0.0") ||
        isInNet(dnsResolve(host),"172.16.0.0","255.240.0.0") ||
        isInNet(dnsResolve(host),"192.168.0.0","255.255.0.0") ||
        isInNet(dnsResolve(host),"127.0.0.0","255.0.0.0") ||
        isPlainHostName(host)) { return "DIRECT"; }
    return "%s";
}
`, username, proxyAddr)
	}

	// Build JS array of regex strings
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("// PAC for user: %s — restricted to %d pattern(s)\n", username, len(patterns)))
	sb.WriteString("function FindProxyForURL(url, host) {\n")
	sb.WriteString("    var patterns = [\n")
	for i, p := range patterns {
		comma := ","
		if i == len(patterns)-1 {
			comma = ""
		}
		// Escape backslashes for JS string literal
		escaped := strings.ReplaceAll(p, `\`, `\\`)
		sb.WriteString(fmt.Sprintf("        /%s/i%s\n", escaped, comma))
	}
	sb.WriteString("    ];\n")
	sb.WriteString("    for (var i = 0; i < patterns.length; i++) {\n")
	sb.WriteString("        if (patterns[i].test(host) || patterns[i].test(url)) {\n")
	sb.WriteString(fmt.Sprintf("            return \"%s\";\n", proxyAddr))
	sb.WriteString("        }\n")
	sb.WriteString("    }\n")
	sb.WriteString("    return \"DIRECT\";\n")
	sb.WriteString("}\n")
	return sb.String()
}

// ─── GitHub OAuth handlers ────────────────────────────────────────────────────

func (h *Handler) handleAuthLogin(w http.ResponseWriter, r *http.Request) {
	if !h.githubAuth.Enabled {
		writeJSON(w, http.StatusOK, map[string]any{"enabled": false, "message": "GitHub auth not configured"})
		return
	}
	callbackURL := publicURL(r) + "/auth/callback"
	http.Redirect(w, r, h.githubAuth.AuthURL(callbackURL), http.StatusFound)
}

func (h *Handler) handleAuthCallback(w http.ResponseWriter, r *http.Request) {
	if !h.githubAuth.Enabled {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")
	callbackURL := publicURL(r) + "/auth/callback"

	user, err := h.githubAuth.Exchange(r.Context(), code, state, callbackURL)
	if err != nil {
		http.Error(w, "Auth failed: "+err.Error(), http.StatusUnauthorized)
		return
	}
	if err := auth.IssueSession(w, user.Login, 24*time.Hour); err != nil {
		http.Error(w, "Session error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/", http.StatusFound)
}

func (h *Handler) handleAuthLogout(w http.ResponseWriter, _ *http.Request) {
	auth.ClearSession(w)
	writeJSON(w, http.StatusOK, map[string]string{"status": "logged out"})
}

func (h *Handler) handleAuthStatus(w http.ResponseWriter, r *http.Request) {
	if !h.githubAuth.Enabled {
		writeJSON(w, http.StatusOK, map[string]any{"auth_enabled": false, "logged_in": true, "login": "anonymous"})
		return
	}
	claims, ok := auth.ValidateSession(r)
	if !ok {
		writeJSON(w, http.StatusOK, map[string]any{"auth_enabled": true, "logged_in": false})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"auth_enabled": true, "logged_in": true, "login": claims.Login})
}

// ─── helpers ─────────────────────────────────────────────────────────────────

// reloadProxy rebuilds v2ray config with latest users and restarts.
func (h *Handler) reloadProxy() {
	accts := h.userStore.AccountsForV2Ray()
	mapped := make([]proxy.UserAccount, len(accts))
	for i, a := range accts {
		mapped[i] = proxy.UserAccount{
			Username:  a.Username,
			Token:     a.Token,
			VMessUUID: a.VMessUUID,
			Patterns:  a.Patterns,
		}
	}
	go func() {
		if err := h.proxyMgr.SetAccounts(mapped); err != nil {
			// log only, don't fail the user API call
			_ = err
		}
	}()
}

// publicURL returns the base URL of the request (scheme + host).
func publicURL(r *http.Request) string {
	if v := os.Getenv("PUBLIC_URL"); v != "" {
		return strings.TrimRight(v, "/")
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return scheme + "://" + r.Host
}

func splitHost(hostport string) (string, string, error) {
	for i := len(hostport) - 1; i >= 0; i-- {
		if hostport[i] == ':' {
			return hostport[:i], hostport[i+1:], nil
		}
	}
	return hostport, "", nil
}

type proxyStatusExt struct {
	Running    bool   `json:"running"`
	HTTPPort   int    `json:"http_port"`
	Socks5Port int    `json:"socks5_port"`
	VMessPort  int    `json:"vmess_port"`
	Error      string `json:"error,omitempty"`
}

func toStatusExt(s proxy.Status, vMessPort int) proxyStatusExt {
	return proxyStatusExt{
		Running:    s.Running,
		HTTPPort:   s.HTTPPort,
		Socks5Port: s.Socks5Port,
		VMessPort:  vMessPort,
		Error:      s.Error,
	}
}

// proxyInfoExtended extends proxyInfoResponse with VMess info.
type proxyInfoExtended struct {
	HostIP     string `json:"host_ip"`
	HTTPPort   int    `json:"http_port"`
	Socks5Port int    `json:"socks5_port"`
	VMessPort  int    `json:"vmess_port"`
	HTTPProxy  string `json:"http_proxy"`
	Socks5     string `json:"socks5"`
	PACUrl     string `json:"pac_url"`
	AuthMode   bool   `json:"auth_mode"` // true when proxy users exist
}

// Users returns users from store — alias used by handlers_users for clarity.
func (h *Handler) store() *users.Store {
	return h.userStore
}
