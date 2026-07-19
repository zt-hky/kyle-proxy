package api

import (
	"net/http"
	"os"
	"strings"
	"time"

	"globalprotect-manager/internal/auth"
)

func (h *Handler) handleAuthLogin(w http.ResponseWriter, r *http.Request) {
	if !h.githubAuth.Enabled {
		writeJSON(w, http.StatusOK, map[string]any{"enabled": false, "message": "GitHub auth not configured"})
		return
	}
	http.Redirect(w, r, h.githubAuth.AuthURL(publicURL(r)+"/auth/callback"), http.StatusFound)
}

func (h *Handler) handleAuthCallback(w http.ResponseWriter, r *http.Request) {
	if !h.githubAuth.Enabled {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	user, err := h.githubAuth.Exchange(r.Context(), r.URL.Query().Get("code"), r.URL.Query().Get("state"), publicURL(r)+"/auth/callback")
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
