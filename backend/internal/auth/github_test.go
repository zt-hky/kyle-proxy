package auth

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
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
