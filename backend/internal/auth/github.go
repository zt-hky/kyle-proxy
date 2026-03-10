package auth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
)

// GitHubUser is a partial GitHub API /user response.
type GitHubUser struct {
	Login string `json:"login"`
	ID    int64  `json:"id"`
	Name  string `json:"name"`
}

// GitHubAuth implements optional GitHub OAuth2 login for the management UI.
// When GITHUB_CLIENT_ID env var is not set, Enabled = false and no auth is enforced.
type GitHubAuth struct {
	conf    *oauth2.Config
	allowed map[string]bool // lowercase GitHub logins; empty = allow any authenticated user
	states  map[string]time.Time
	mu      sync.Mutex
	Enabled bool
}

// NewGitHubAuth reads env vars GITHUB_CLIENT_ID, GITHUB_CLIENT_SECRET, GITHUB_ALLOWED_USERS.
func NewGitHubAuth() *GitHubAuth {
	ga := &GitHubAuth{
		allowed: make(map[string]bool),
		states:  make(map[string]time.Time),
	}
	clientID := os.Getenv("GITHUB_CLIENT_ID")
	if clientID == "" {
		return ga // Enabled = false
	}
	ga.Enabled = true
	ga.conf = &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: os.Getenv("GITHUB_CLIENT_SECRET"),
		Scopes:       []string{"read:user"},
		Endpoint:     github.Endpoint,
	}
	for _, u := range strings.Split(os.Getenv("GITHUB_ALLOWED_USERS"), ",") {
		if u = strings.TrimSpace(strings.ToLower(u)); u != "" {
			ga.allowed[u] = true
		}
	}
	return ga
}

// AuthURL returns the GitHub OAuth2 redirect URL with a random state token.
func (ga *GitHubAuth) AuthURL(callbackURL string) string {
	ga.mu.Lock()
	defer ga.mu.Unlock()
	state := randHex(8)
	ga.states[state] = time.Now()
	// purge stale states
	for s, t := range ga.states {
		if time.Since(t) > 15*time.Minute {
			delete(ga.states, s)
		}
	}
	c := *ga.conf
	c.RedirectURL = callbackURL
	return c.AuthCodeURL(state, oauth2.AccessTypeOnline)
}

// Exchange validates state, exchanges code for token, fetches GitHub user.
// Returns error if the user is not in the allowed list.
func (ga *GitHubAuth) Exchange(ctx context.Context, code, state, callbackURL string) (*GitHubUser, error) {
	ga.mu.Lock()
	_, ok := ga.states[state]
	if ok {
		delete(ga.states, state)
	}
	ga.mu.Unlock()
	if !ok {
		return nil, fmt.Errorf("invalid or expired OAuth state")
	}

	c := *ga.conf
	c.RedirectURL = callbackURL
	tok, err := c.Exchange(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("token exchange: %w", err)
	}

	req, _ := http.NewRequestWithContext(ctx, "GET", "https://api.github.com/user", nil)
	req.Header.Set("Authorization", "token "+tok.AccessToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("github /user: %w", err)
	}
	defer resp.Body.Close()

	var u GitHubUser
	if err := json.NewDecoder(resp.Body).Decode(&u); err != nil {
		return nil, fmt.Errorf("decode user: %w", err)
	}
	if len(ga.allowed) > 0 && !ga.allowed[strings.ToLower(u.Login)] {
		return nil, fmt.Errorf("GitHub user %q is not in the allowed list", u.Login)
	}
	return &u, nil
}

// randHex generates a cryptographically random lowercase hex string.
func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// Middleware protects all routes requiring authentication.
// Public paths: /auth/*, /api/health, /pac, /pac/*
// If auth is disabled (Enabled = false), this is a no-op.
func (ga *GitHubAuth) Middleware(next http.Handler) http.Handler {
	if !ga.Enabled {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		switch {
		case path == "/auth/login",
			path == "/auth/callback",
			path == "/auth/logout",
			path == "/api/health",
			path == "/pac",
			strings.HasPrefix(path, "/pac/"):
			next.ServeHTTP(w, r)
			return
		}
		if _, ok := ValidateSession(r); ok {
			next.ServeHTTP(w, r)
			return
		}
		if strings.HasPrefix(path, "/api/") {
			w.Header().Set("Content-Type", "application/json")
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}
		// SPA handles the login redirect
		http.Redirect(w, r, "/?auth=required", http.StatusFound)
	})
}
