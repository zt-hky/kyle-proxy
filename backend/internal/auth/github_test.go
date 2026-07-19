package auth

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"golang.org/x/oauth2"
)

func TestMiddlewarePublicPathsExcludePAC(t *testing.T) {
	ga := &GitHubAuth{Enabled: true}
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	handler := ga.Middleware(next)

	for _, tc := range []struct {
		path string
		want int
	}{
		{"/api/health", http.StatusNoContent},
		{"/auth/login", http.StatusNoContent},
		{"/pac", http.StatusFound},
		{"/pac/alice", http.StatusFound},
		{"/api/status", http.StatusUnauthorized},
	} {
		t.Run(tc.path, func(t *testing.T) {
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, tc.path, nil))
			if response.Code != tc.want {
				t.Fatalf("code = %d, want %d", response.Code, tc.want)
			}
			if tc.path == "/api/status" && !strings.Contains(response.Body.String(), "unauthorized") {
				t.Fatalf("body = %q", response.Body.String())
			}
		})
	}
}

func TestSessionUsesRenamedCookieAndAuthorizesRequest(t *testing.T) {
	t.Setenv("AUTH_SECRET", "test-secret")
	issued := httptest.NewRecorder()
	if err := IssueSession(issued, "alice", 60_000_000_000); err != nil {
		t.Fatal(err)
	}
	cookies := issued.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != "globalprotect_manager_session" {
		t.Fatalf("cookies = %+v", cookies)
	}

	request := httptest.NewRequest(http.MethodGet, "/api/status", nil)
	request.AddCookie(cookies[0])
	claims, ok := ValidateSession(request)
	if !ok || claims.Login != "alice" {
		t.Fatalf("claims = %+v, ok = %v", claims, ok)
	}

	called := false
	handler := (&GitHubAuth{Enabled: true}).Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { called = true; w.WriteHeader(http.StatusNoContent) }))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if !called || response.Code != http.StatusNoContent {
		t.Fatalf("called=%v code=%d", called, response.Code)
	}
}

func TestDisabledMiddlewareIsNoOp(t *testing.T) {
	called := false
	handler := (&GitHubAuth{}).Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { called = true; w.WriteHeader(http.StatusAccepted) }))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/api/status", nil))
	if !called || response.Code != http.StatusAccepted {
		t.Fatalf("called=%v code=%d", called, response.Code)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

func TestNewGitHubAuthEnvironment(t *testing.T) {
	t.Run("disabled", func(t *testing.T) {
		t.Setenv("GITHUB_CLIENT_ID", "")
		ga := NewGitHubAuth()
		if ga.Enabled || ga.conf != nil || len(ga.allowed) != 0 {
			t.Fatalf("unexpected disabled config: %+v", ga)
		}
	})
	t.Run("enabled and allowed users normalized", func(t *testing.T) {
		t.Setenv("GITHUB_CLIENT_ID", "client")
		t.Setenv("GITHUB_CLIENT_SECRET", "secret")
		t.Setenv("GITHUB_ALLOWED_USERS", " Alice,BOB, ,alice ")
		ga := NewGitHubAuth()
		if !ga.Enabled || ga.conf.ClientID != "client" || ga.conf.ClientSecret != "secret" {
			t.Fatalf("unexpected config: %+v", ga.conf)
		}
		if len(ga.allowed) != 2 || !ga.allowed["alice"] || !ga.allowed["bob"] {
			t.Fatalf("allowed = %#v", ga.allowed)
		}
	})
}

func TestAuthURLStoresStateAndPurgesStaleStates(t *testing.T) {
	t.Setenv("GITHUB_CLIENT_ID", "client")
	ga := NewGitHubAuth()
	ga.states["stale"] = time.Now().Add(-16 * time.Minute)
	authURL := ga.AuthURL("https://manager.example/auth/callback")
	parsed, err := url.Parse(authURL)
	if err != nil {
		t.Fatal(err)
	}
	state := parsed.Query().Get("state")
	if state == "" || parsed.Query().Get("redirect_uri") != "https://manager.example/auth/callback" {
		t.Fatalf("auth URL = %q", authURL)
	}
	if _, ok := ga.states[state]; !ok {
		t.Fatalf("state %q was not stored", state)
	}
	if _, ok := ga.states["stale"]; ok {
		t.Fatal("stale state was not purged")
	}
}

func TestExchangeBranches(t *testing.T) {
	newAuth := func() *GitHubAuth {
		return &GitHubAuth{
			conf:    &oauth2.Config{},
			allowed: map[string]bool{"alice": true},
			states:  map[string]time.Time{"valid": time.Now()},
			exchange: func(_ context.Context, c *oauth2.Config, code string) (*oauth2.Token, error) {
				if code != "code" || c.RedirectURL != "https://manager.example/callback" {
					return nil, errors.New("unexpected exchange arguments")
				}
				return &oauth2.Token{AccessToken: "token"}, nil
			},
		}
	}
	t.Run("invalid state", func(t *testing.T) {
		ga := newAuth()
		if _, err := ga.Exchange(context.Background(), "code", "bad", "callback"); err == nil || !strings.Contains(err.Error(), "state") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("token exchange failure consumes state", func(t *testing.T) {
		ga := newAuth()
		ga.exchange = func(context.Context, *oauth2.Config, string) (*oauth2.Token, error) {
			return nil, errors.New("denied")
		}
		if _, err := ga.Exchange(context.Background(), "code", "valid", "callback"); err == nil || !strings.Contains(err.Error(), "token exchange") {
			t.Fatalf("err = %v", err)
		}
		if _, ok := ga.states["valid"]; ok {
			t.Fatal("state was not consumed")
		}
	})
	t.Run("HTTP failure", func(t *testing.T) {
		ga := newAuth()
		ga.client = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return nil, errors.New("offline")
		})}
		if _, err := ga.Exchange(context.Background(), "code", "valid", "https://manager.example/callback"); err == nil || !strings.Contains(err.Error(), "github /user") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("decode failure", func(t *testing.T) {
		ga := newAuth()
		ga.client = responseClient("not-json", nil)
		if _, err := ga.Exchange(context.Background(), "code", "valid", "https://manager.example/callback"); err == nil || !strings.Contains(err.Error(), "decode user") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("disallowed user", func(t *testing.T) {
		ga := newAuth()
		ga.client = responseClient(`{"login":"mallory","id":7}`, nil)
		if _, err := ga.Exchange(context.Background(), "code", "valid", "https://manager.example/callback"); err == nil || !strings.Contains(err.Error(), "allowed list") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("allowed user case insensitive", func(t *testing.T) {
		ga := newAuth()
		var authorization string
		ga.client = responseClient(`{"login":"Alice","id":7,"name":"Alice A"}`, &authorization)
		user, err := ga.Exchange(context.Background(), "code", "valid", "https://manager.example/callback")
		if err != nil || user.Login != "Alice" || user.ID != 7 || authorization != "token token" {
			t.Fatalf("user=%+v authorization=%q err=%v", user, authorization, err)
		}
	})
	t.Run("empty allowed list permits user", func(t *testing.T) {
		ga := newAuth()
		ga.allowed = map[string]bool{}
		ga.client = responseClient(`{"login":"anyone"}`, nil)
		if _, err := ga.Exchange(context.Background(), "code", "valid", "https://manager.example/callback"); err != nil {
			t.Fatal(err)
		}
	})
}

func responseClient(body string, authorization *string) *http.Client {
	return &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if authorization != nil {
			*authorization = r.Header.Get("Authorization")
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(body)),
			Header:     make(http.Header),
		}, nil
	})}
}

func TestMiddlewareAllPublicAndProtectedPaths(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	handler := (&GitHubAuth{Enabled: true}).Middleware(next)
	for _, path := range []string{"/auth/login", "/auth/callback", "/auth/logout", "/api/health"} {
		t.Run(path, func(t *testing.T) {
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
			if w.Code != http.StatusNoContent {
				t.Fatalf("code = %d", w.Code)
			}
		})
	}
	api := httptest.NewRecorder()
	handler.ServeHTTP(api, httptest.NewRequest(http.MethodGet, "/api/private", nil))
	if api.Code != http.StatusUnauthorized || !strings.Contains(api.Body.String(), "unauthorized") {
		t.Fatalf("API response: code=%d body=%q", api.Code, api.Body.String())
	}
	ui := httptest.NewRecorder()
	handler.ServeHTTP(ui, httptest.NewRequest(http.MethodGet, "/settings", nil))
	if ui.Code != http.StatusFound || ui.Header().Get("Location") != "/?auth=required" {
		t.Fatalf("UI response: code=%d location=%q", ui.Code, ui.Header().Get("Location"))
	}
}

func TestSessionLifecycleAndCookieAttributes(t *testing.T) {
	t.Setenv("AUTH_SECRET", "production-secret")
	w := httptest.NewRecorder()
	if err := IssueSession(w, "alice", time.Minute); err != nil {
		t.Fatal(err)
	}
	cookie := w.Result().Cookies()[0]
	if cookie.Name != sessionCookie || cookie.Path != "/" || !cookie.HttpOnly ||
		cookie.SameSite != http.SameSiteLaxMode || cookie.MaxAge != 60 {
		t.Fatalf("cookie = %+v", cookie)
	}
	valid := httptest.NewRequest(http.MethodGet, "/", nil)
	valid.AddCookie(cookie)
	claims, ok := ValidateSession(valid)
	if !ok || claims.Login != "alice" || claims.ExpiresAt == nil || claims.IssuedAt == nil {
		t.Fatalf("claims=%+v ok=%v", claims, ok)
	}

	tampered := httptest.NewRequest(http.MethodGet, "/", nil)
	tamperedCookie := *cookie
	tamperedCookie.Value += "x"
	tampered.AddCookie(&tamperedCookie)
	if _, ok := ValidateSession(tampered); ok {
		t.Fatal("tampered token validated")
	}
	if _, ok := ValidateSession(httptest.NewRequest(http.MethodGet, "/", nil)); ok {
		t.Fatal("request without cookie validated")
	}

	expiredWriter := httptest.NewRecorder()
	if err := IssueSession(expiredWriter, "alice", -time.Second); err != nil {
		t.Fatal(err)
	}
	expired := httptest.NewRequest(http.MethodGet, "/", nil)
	expired.AddCookie(expiredWriter.Result().Cookies()[0])
	if _, ok := ValidateSession(expired); ok {
		t.Fatal("expired token validated")
	}

	cleared := httptest.NewRecorder()
	ClearSession(cleared)
	clearCookie := cleared.Result().Cookies()[0]
	if clearCookie.Name != sessionCookie || clearCookie.Value != "" || clearCookie.Path != "/" || clearCookie.MaxAge != -1 {
		t.Fatalf("clear cookie = %+v", clearCookie)
	}
}

func TestJWTSecretSelection(t *testing.T) {
	t.Setenv("AUTH_SECRET", "chosen")
	if got := string(jwtSecret()); got != "chosen" {
		t.Fatalf("secret = %q", got)
	}
	t.Setenv("AUTH_SECRET", "")
	if got := string(jwtSecret()); got != "globalprotect-manager-dev-secret-change-me" {
		t.Fatalf("fallback secret = %q", got)
	}
}
