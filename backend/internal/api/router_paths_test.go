package api

import (
	"io/fs"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"globalprotect-manager/internal/auth"
	"globalprotect-manager/internal/config"
	"globalprotect-manager/internal/control"
	"globalprotect-manager/internal/vpn"
)

func routerWithFS(t *testing.T, files fs.FS) http.Handler {
	t.Helper()
	m := config.NewManager(t.TempDir() + "/config.json")
	m.Load()
	return NewRouter(control.NewVPN(vpn.NewManager(), m), m, auth.NewGitHubAuth(), files)
}

func TestRouterHealthCORSAndDevelopmentFallback(t *testing.T) {
	r := routerWithFS(t, nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/health", nil))
	if w.Code != http.StatusOK || w.Header().Get("Access-Control-Allow-Origin") != "*" {
		t.Fatalf("health = %d %v", w.Code, w.Header())
	}
	w = httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodOptions, "/api/config", nil))
	if w.Code != http.StatusNoContent || w.Header().Get("Access-Control-Allow-Methods") == "" || w.Header().Get("Access-Control-Allow-Headers") == "" {
		t.Fatalf("options = %d %v", w.Code, w.Header())
	}
	w = httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))
	if w.Code != http.StatusTemporaryRedirect || w.Header().Get("Location") != "http://localhost:5173" {
		t.Fatalf("dev redirect = %d %q", w.Code, w.Header().Get("Location"))
	}
}

func TestStaticServingFallbackAndAPINotFound(t *testing.T) {
	files := fstest.MapFS{
		"index.html": {Data: []byte("INDEX")},
		"app.js":     {Data: []byte("JS")},
	}
	r := routerWithFS(t, files)
	for _, tt := range []struct {
		path, body string
		code       int
	}{
		{"/", "INDEX", 200}, {"/app.js", "JS", 200}, {"/client/route", "", 301},
		{"/api/missing", "404", 404}, {"/pac", "404", 404}, {"/pac/file", "404", 404},
	} {
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, tt.path, nil))
		if w.Code != tt.code || !strings.Contains(w.Body.String(), tt.body) {
			t.Errorf("%s = %d %q", tt.path, w.Code, w.Body.String())
		}
	}
}

func TestAuthDisabledHandlersAndPublicURL(t *testing.T) {
	h, _ := testHandler(t, &fakeController{})
	for _, fn := range []http.HandlerFunc{h.handleAuthLogin, h.handleAuthStatus} {
		w := call(fn, http.MethodGet, "http://example.test/", "")
		if w.Code != http.StatusOK {
			t.Fatalf("disabled auth = %d %s", w.Code, w.Body.String())
		}
	}
	w := call(h.handleAuthCallback, http.MethodGet, "http://example.test/auth/callback", "")
	if w.Code != http.StatusFound || w.Header().Get("Location") != "/" {
		t.Fatalf("callback = %d %q", w.Code, w.Header().Get("Location"))
	}
	w = call(h.handleAuthLogout, http.MethodPost, "/", "")
	if w.Code != http.StatusOK || len(w.Result().Cookies()) == 0 {
		t.Fatalf("logout = %d", w.Code)
	}
	r := httptest.NewRequest(http.MethodGet, "http://internal/path", nil)
	if got := publicURL(r); got != "http://internal" {
		t.Fatalf("publicURL = %q", got)
	}
}

func TestPublicURLAndEnabledAuthErrors(t *testing.T) {
	t.Setenv("PUBLIC_URL", "https://public.example///")
	r := httptest.NewRequest(http.MethodGet, "http://internal/", nil)
	if got := publicURL(r); got != "https://public.example" {
		t.Fatalf("PUBLIC_URL = %q", got)
	}
	t.Setenv("PUBLIC_URL", "")
	r = httptest.NewRequest(http.MethodGet, "https://secure.example/", nil)
	if got := publicURL(r); got != "https://secure.example" {
		t.Fatalf("TLS URL = %q", got)
	}

	t.Setenv("GITHUB_CLIENT_ID", "client")
	ga := auth.NewGitHubAuth()
	m := config.NewManager(t.TempDir() + "/config.json")
	m.Load()
	h := newHandler(&fakeController{}, m, ga)
	w := call(h.handleAuthLogin, http.MethodGet, "http://host/auth/login", "")
	if w.Code != http.StatusFound || !strings.Contains(w.Header().Get("Location"), "github.com/login/oauth/authorize") {
		t.Fatalf("login = %d %q", w.Code, w.Header().Get("Location"))
	}
	w = call(h.handleAuthCallback, http.MethodGet, "http://host/auth/callback?state=bad", "")
	if w.Code != http.StatusUnauthorized || !strings.Contains(w.Body.String(), "invalid or expired") {
		t.Fatalf("callback error = %d %s", w.Code, w.Body.String())
	}
	w = call(h.handleAuthStatus, http.MethodGet, "/", "")
	if !strings.Contains(w.Body.String(), `"logged_in":false`) {
		t.Fatalf("logged out = %s", w.Body.String())
	}

	t.Setenv("SESSION_SECRET", "01234567890123456789012345678901")
	cookieWriter := httptest.NewRecorder()
	if err := auth.IssueSession(cookieWriter, "alice", time.Hour); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(cookieWriter.Result().Cookies()[0])
	w = httptest.NewRecorder()
	h.handleAuthStatus(w, req)
	if !strings.Contains(w.Body.String(), `"logged_in":true`) || !strings.Contains(w.Body.String(), `"login":"alice"`) {
		t.Fatalf("logged in = %s", w.Body.String())
	}
}
