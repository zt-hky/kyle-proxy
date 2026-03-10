package api

import (
	"io/fs"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"kyle-proxy/internal/config"
	"kyle-proxy/internal/proxy"
	"kyle-proxy/internal/vpn"
)

// NewRouter builds and returns the HTTP router.
// staticFS is the embedded Svelte build output; pass nil for dev mode.
func NewRouter(
	v *vpn.Manager,
	p *proxy.Manager,
	c *config.Manager,
	staticFS fs.FS,
) http.Handler {
	h := newHandler(v, p, c)

	r := chi.NewRouter()
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(corsMiddleware)

	// ── API routes ───────────────────────────────────────────────────────────
	r.Get("/api/health", h.handleHealth)
	r.Get("/api/status", h.handleStatus)

	r.Get("/api/config", h.handleGetConfig)
	r.Put("/api/config", h.handleUpdateConfig)
	r.Post("/api/config", h.handleUpdateConfig) // also accept POST for convenience

	r.Post("/api/vpn/connect", h.handleConnect)
	r.Post("/api/vpn/disconnect", h.handleDisconnect)

	r.Get("/api/logs", h.handleLogs)
	r.Get("/api/proxy/info", h.handleProxyInfo)

	r.Post("/api/certs/upload", h.handleCertUpload)

	// ── PAC file ─────────────────────────────────────────────────────────────
	r.Get("/pac", h.handlePAC)

	// ── Static SPA ───────────────────────────────────────────────────────────
	if staticFS != nil {
		staticServer := http.FileServer(http.FS(staticFS))
		r.Get("/*", func(w http.ResponseWriter, r *http.Request) {
			// For SPA routing: serve index.html for unknown paths
			path := strings.TrimPrefix(r.URL.Path, "/")
			if path == "" {
				path = "index.html"
			}
			// Try to serve the file; fall back to index.html for SPA routing
			f, err := staticFS.Open(path)
			if err != nil {
				r.URL.Path = "/index.html"
			} else {
				f.Close()
			}
			staticServer.ServeHTTP(w, r)
		})
	} else {
		// Dev mode: show a simple redirect hint
		r.Get("/", func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "http://localhost:5173", http.StatusTemporaryRedirect)
		})
	}

	return r
}

// corsMiddleware allows all origins in development; tighten in production if needed
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
