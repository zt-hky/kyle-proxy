package api

import (
	"io/fs"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"globalprotect-manager/internal/auth"
	"globalprotect-manager/internal/config"
	"globalprotect-manager/internal/control"
)

// NewRouter builds and returns the HTTP router.
// staticFS is the embedded Svelte build output; pass nil for dev mode.
func NewRouter(
	controller *control.VPN,
	c *config.Manager,
	ga *auth.GitHubAuth,
	staticFS fs.FS,
) http.Handler {
	h := newHandler(controller, c, ga)

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
	r.Post("/api/vpn/otp", h.handleVPNOTP)
	r.Post("/api/vpn/disconnect", h.handleDisconnect)

	r.Get("/api/logs", h.handleLogs)

	r.Post("/api/certs/upload", h.handleCertUpload)

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
				if strings.HasPrefix(path, "api/") || path == "pac" || strings.HasPrefix(path, "pac/") {
					http.NotFound(w, r)
					return
				}
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
