package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
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

func TestLoadMissingAndCorruptReturnDefaults(t *testing.T) {
	missing := NewManager(filepath.Join(t.TempDir(), "missing.json"))
	if got := missing.Load(); !reflect.DeepEqual(got.VPN, VPNConfig{}) {
		t.Fatalf("missing config = %+v", got)
	}

	path := filepath.Join(t.TempDir(), "corrupt.json")
	if err := os.WriteFile(path, []byte(`{"vpn":`), 0600); err != nil {
		t.Fatal(err)
	}
	if got := NewManager(path).Load(); !reflect.DeepEqual(got.VPN, VPNConfig{}) {
		t.Fatalf("corrupt config = %+v", got)
	}
}

func TestGetBeforeLoadReturnsDefaultAndDeepCopy(t *testing.T) {
	manager := NewManager(filepath.Join(t.TempDir(), "config.json"))
	if got := manager.Get(); !reflect.DeepEqual(got.VPN, VPNConfig{}) {
		t.Fatalf("before load = %+v", got)
	}
	want := &AppConfig{VPN: VPNConfig{ExtraArgs: []string{"--one"}}}
	if err := manager.Save(want); err != nil {
		t.Fatal(err)
	}
	want.VPN.ExtraArgs[0] = "--mutated-input"
	if manager.Get().VPN.ExtraArgs[0] != "--one" {
		t.Fatal("Save retained an ExtraArgs slice alias")
	}
	got := manager.Get()
	got.VPN.ExtraArgs[0] = "--mutated"
	if manager.Get().VPN.ExtraArgs[0] != "--one" {
		t.Fatal("Get returned an ExtraArgs slice alias")
	}
}

func TestSaveCreatesDirectoryPersistsAndSetsPrivatePermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "config.json")
	manager := NewManager(path)
	want := &AppConfig{VPN: VPNConfig{Portal: "vpn.example", ExtraArgs: []string{"--one"}}}
	if err := manager.Save(want); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("mode = %o, want 600", info.Mode().Perm())
	}
	if got := NewManager(path).Load(); got.VPN.Portal != want.VPN.Portal {
		t.Fatalf("loaded = %+v", got)
	}
}

func TestSaveAndUpdateReportFilesystemErrors(t *testing.T) {
	t.Run("create directory", func(t *testing.T) {
		parent := filepath.Join(t.TempDir(), "file")
		if err := os.WriteFile(parent, []byte("not a directory"), 0600); err != nil {
			t.Fatal(err)
		}
		manager := NewManager(filepath.Join(parent, "config.json"))
		if err := manager.Save(Default()); err == nil {
			t.Fatal("Save succeeded with a file as its parent directory")
		}
		if err := manager.UpdateVPN(VPNConfig{Portal: "vpn.example"}); err == nil {
			t.Fatal("UpdateVPN succeeded with a file as its parent directory")
		}
	})

	t.Run("write file", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "config.json")
		if err := os.Mkdir(path, 0700); err != nil {
			t.Fatal(err)
		}
		manager := NewManager(path)
		if err := manager.Save(Default()); err == nil {
			t.Fatal("Save succeeded when config path is a directory")
		}
		if err := manager.UpdateVPN(VPNConfig{Portal: "vpn.example"}); err == nil {
			t.Fatal("UpdateVPN succeeded when config path is a directory")
		}
	})
}

func TestUpdateVPNBeforeLoadPersistsAllFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	manager := NewManager(path)
	want := VPNConfig{Portal: "vpn.example", Username: "alice", ExtraArgs: []string{"--one"}}
	if err := manager.UpdateVPN(want); err != nil {
		t.Fatal(err)
	}
	want.ExtraArgs[0] = "--mutated-input"
	if manager.Get().VPN.ExtraArgs[0] != "--one" {
		t.Fatal("UpdateVPN retained an ExtraArgs slice alias")
	}
	if got := NewManager(path).Load().VPN; got.ExtraArgs[0] != "--one" || got.Portal != want.Portal || got.Username != want.Username {
		t.Fatalf("loaded = %+v", got)
	}
}
