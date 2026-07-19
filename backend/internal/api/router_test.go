package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"globalprotect-manager/internal/auth"
	"globalprotect-manager/internal/config"
	"globalprotect-manager/internal/control"
	"globalprotect-manager/internal/vpn"
)

func testRouter(t *testing.T) http.Handler {
	t.Helper()
	cfg := config.NewManager(t.TempDir() + "/config.json")
	cfg.Load()
	return NewRouter(control.NewVPN(vpn.NewManager(), cfg), cfg, auth.NewGitHubAuth(), nil)
}

func TestStatusAndConfigContractsExcludeRemovedSharingFields(t *testing.T) {
	router := testRouter(t)

	status := httptest.NewRecorder()
	router.ServeHTTP(status, httptest.NewRequest(http.MethodGet, "/api/status", nil))
	if status.Code != http.StatusOK {
		t.Fatalf("status code = %d", status.Code)
	}
	var statusBody map[string]json.RawMessage
	if err := json.Unmarshal(status.Body.Bytes(), &statusBody); err != nil {
		t.Fatal(err)
	}
	if len(statusBody) != 1 || statusBody["vpn"] == nil {
		t.Fatalf("unexpected status keys: %v", statusBody)
	}

	cfg := httptest.NewRecorder()
	router.ServeHTTP(cfg, httptest.NewRequest(http.MethodGet, "/api/config", nil))
	if cfg.Code != http.StatusOK {
		t.Fatalf("config code = %d", cfg.Code)
	}
	var configBody map[string]json.RawMessage
	if err := json.Unmarshal(cfg.Body.Bytes(), &configBody); err != nil {
		t.Fatal(err)
	}
	for _, removed := range []string{"http_port", "socks5_port", "vmess_port", "server_host"} {
		if _, ok := configBody[removed]; ok {
			t.Fatalf("removed field %q present", removed)
		}
	}
}

func TestRemovedEndpointsReturnNotFound(t *testing.T) {
	router := testRouter(t)
	for _, path := range []string{"/api/proxy/info", "/api/users", "/api/groups", "/pac"} {
		t.Run(path, func(t *testing.T) {
			response := httptest.NewRecorder()
			router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))
			if response.Code != http.StatusNotFound {
				t.Fatalf("code = %d", response.Code)
			}
		})
	}
}

func TestConnectPreservesHTTPValidationAndMalformedBodyBehavior(t *testing.T) {
	router := testRouter(t)
	for _, body := range []string{"{}", "{"} {
		response := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodPost, "/api/vpn/connect", strings.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(response, request)
		if response.Code != http.StatusBadRequest {
			t.Fatalf("body %q: code = %d", body, response.Code)
		}
		var result map[string]string
		if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		if result["error"] != "VPN portal and username must be configured first" {
			t.Fatalf("body %q: error = %q", body, result["error"])
		}
	}
}

func TestConfigUpdateRejectsInvalidTOTPAndPersistsVPNOnly(t *testing.T) {
	router := testRouter(t)
	invalid := httptest.NewRecorder()
	router.ServeHTTP(invalid, httptest.NewRequest(http.MethodPut, "/api/config", strings.NewReader(`{"portal":"vpn.example","username":"alice","otp_secret":"%%%"}`)))
	if invalid.Code != http.StatusBadRequest {
		t.Fatalf("invalid TOTP code = %d", invalid.Code)
	}

	valid := httptest.NewRecorder()
	router.ServeHTTP(valid, httptest.NewRequest(http.MethodPut, "/api/config", strings.NewReader(`{"portal":"vpn.example","gateway":"gw","username":"alice","password":"secret","trust_cert":true,"extra_args":["--no-dtls"]}`)))
	if valid.Code != http.StatusOK {
		t.Fatalf("valid update code = %d: %s", valid.Code, valid.Body.String())
	}
	get := httptest.NewRecorder()
	router.ServeHTTP(get, httptest.NewRequest(http.MethodGet, "/api/config", nil))
	var response map[string]json.RawMessage
	if err := json.Unmarshal(get.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if _, ok := response["password"]; ok {
		t.Fatal("password field leaked from config response")
	}
	if string(response["has_password"]) != "true" {
		t.Fatalf("has_password = %s", response["has_password"])
	}
	if strings.Contains(get.Body.String(), "http_port") {
		t.Fatal("removed config field returned")
	}
}
