package api

import (
	"io/fs"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"kyle-proxy/internal/auth"
	"kyle-proxy/internal/config"
	"kyle-proxy/internal/proxy"
	"kyle-proxy/internal/users"
	"kyle-proxy/internal/vpn"
)

// NewRouter builds and returns the HTTP router.
// staticFS is the embedded Svelte build output; pass nil for dev mode.
func NewRouter(
	v *vpn.Manager,
	p *proxy.Manager,
	c *config.Manager,
	us *users.Store,
	ga *auth.GitHubAuth,
	staticFS fs.FS,
) http.Handler {
	h := newHandler(v, p, c, us, ga)

	r := chi.NewRouter()
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(corsMiddleware)
	r.Use(ga.Middleware) // no-op when GitHub auth is not configured

	// ── Auth routes (public) ─────────────────────────────────────────────────
	r.Get("/auth/login", h.handleAuthLogin)
	r.Get("/auth/callback", h.handleAuthCallback)
	r.Get("/auth/logout", h.handleAuthLogout)
	r.Get("/api/auth/status", h.handleAuthStatus)

	// ── Core API routes ──────────────────────────────────────────────────────
	r.Get("/api/health", h.handleHealth)
	r.Get("/api/status", h.handleStatus)

	r.Get("/api/config", h.handleGetConfig)
	r.Put("/api/config", h.handleUpdateConfig)
	r.Post("/api/config", h.handleUpdateConfig)

	r.Post("/api/vpn/connect", h.handleConnect)
	r.Post("/api/vpn/disconnect", h.handleDisconnect)

	r.Get("/api/logs", h.handleLogs)
	r.Get("/api/proxy/info", h.handleProxyInfo)

	r.Post("/api/certs/upload", h.handleCertUpload)

	// ── User management API ──────────────────────────────────────────────────
	r.Get("/api/users", h.handleListUsers)
	r.Post("/api/users", h.handleCreateUser)
	r.Put("/api/users/{id}", h.handleUpdateUser)
	r.Delete("/api/users/{id}", h.handleDeleteUser)
	r.Get("/api/users/{id}/vmess", h.handleVMessExport)
	r.Get("/api/users/{id}/v2ray-config", h.handleV2RayClientConfig) // full client config with routing

	// ── Group management API ──────────────────────────────────────────────────
	r.Get("/api/groups", h.handleListGroups)
	r.Post("/api/groups", h.handleCreateGroup)
	r.Put("/api/groups/{id}", h.handleUpdateGroup)
	r.Delete("/api/groups/{id}", h.handleDeleteGroup)

	// ── PAC files (public — no auth required) ────────────────────────────────
	r.Get("/pac", h.handlePAC)
	r.Get("/pac/{username}", h.handleUserPAC)

	// ── Static SPA ───────────────────────────────────────────────────────────
	if staticFS != nil {
		staticServer := http.FileServer(http.FS(staticFS))
		r.Get("/*", func(w http.ResponseWriter, r *http.Request) {
			path := strings.TrimPrefix(r.URL.Path, "/")
			if path == "" {
				path = "index.html"
			}
			f, err := staticFS.Open(path)
			if err != nil {
				r.URL.Path = "/index.html"
			} else {
				f.Close()
			}
			staticServer.ServeHTTP(w, r)
		})
	} else {
		r.Get("/", func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "http://localhost:5173", http.StatusTemporaryRedirect)
		})
	}

	return r
}

// corsMiddleware allows all origins in development; tighten in production if needed.
func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

