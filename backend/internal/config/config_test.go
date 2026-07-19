package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadIgnoresLegacyProxyAndNextSaveDropsIt(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	legacy := []byte(`{"vpn":{"portal":"vpn.example","username":"alice"},"proxy":{"http_port":8080,"server_host":"old"}}`)
	if err := os.WriteFile(path, legacy, 0600); err != nil {
		t.Fatal(err)
	}
	manager := NewManager(path)
	loaded := manager.Load()
	if loaded.VPN.Portal != "vpn.example" || loaded.VPN.Username != "alice" {
		t.Fatalf("loaded = %+v", loaded.VPN)
	}
	loaded.VPN.Gateway = "gateway"
	if err := manager.Save(loaded); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var root map[string]json.RawMessage
	if err := json.Unmarshal(data, &root); err != nil {
		t.Fatal(err)
	}
	if _, exists := root["proxy"]; exists {
		t.Fatalf("legacy proxy persisted: %s", data)
	}
	if len(root) != 1 || root["vpn"] == nil {
		t.Fatalf("unexpected root: %v", root)
	}
}

func TestGetReturnsIndependentConfigCopy(t *testing.T) {
	manager := NewManager(filepath.Join(t.TempDir(), "config.json"))
	manager.Load()
	cfg := manager.Get()
	cfg.VPN.Portal = "mutated"
	cfg.VPN.ExtraArgs = []string{"--one"}
	got := manager.Get()
	if got.VPN.Portal != "" {
		t.Fatalf("manager changed through copy: %+v", got.VPN)
	}
}

func TestUpdateVPNPersistsPrivateFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "config.json")
	manager := NewManager(path)
	manager.Load()
	want := VPNConfig{Portal: "vpn.example", Gateway: "gw", Username: "alice", Password: "password", OTPSecret: "SECRET", AutoReconnect: true, CertFile: "/data/certs/ca.crt", TrustCert: true, ExtraArgs: []string{"--no-dtls"}}
	if err := manager.UpdateVPN(want); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("mode = %o", info.Mode().Perm())
	}
	reloaded := NewManager(path).Load()
	if reloaded.VPN.Portal != want.Portal || reloaded.VPN.Password != want.Password || !reloaded.VPN.AutoReconnect {
		t.Fatalf("reloaded = %+v", reloaded.VPN)
	}
}
