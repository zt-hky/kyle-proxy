package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

const DefaultConfigPath = "/data/config.json"

// AppConfig holds all persistent configuration
type AppConfig struct {
	VPN   VPNConfig   `json:"vpn"`
	Proxy ProxyConfig `json:"proxy"`
}

// VPNConfig stores GlobalProtect VPN settings
type VPNConfig struct {
	Portal    string   `json:"portal"`
	Gateway   string   `json:"gateway,omitempty"`
	Username  string   `json:"username"`
	Password  string   `json:"password"`
	CertFile  string   `json:"cert_file,omitempty"`  // custom CA cert path inside container
	TrustCert bool     `json:"trust_cert"`           // skip TLS verification (--no-certificate-check)
	ExtraArgs []string `json:"extra_args,omitempty"`
}

// ProxyConfig stores v2ray proxy settings
type ProxyConfig struct {
	HTTPPort   int    `json:"http_port"`
	Socks5Port int    `json:"socks5_port"`
	VMessPort  int    `json:"vmess_port"`   // VMess inbound port for v2box/v2ray clients
	ServerHost string `json:"server_host,omitempty"` // public IP/hostname used in vmess:// links
}

// Default returns a config with sensible defaults
func Default() *AppConfig {
	return &AppConfig{
		Proxy: ProxyConfig{
			HTTPPort:   8080,
			Socks5Port: 1080,
			VMessPort:  8388,
		},
	}
}

// Manager manages loading and saving config with thread safety
type Manager struct {
	mu         sync.RWMutex
	cfg        *AppConfig
	configPath string
}

// NewManager creates a new config manager
func NewManager(configPath string) *Manager {
	return &Manager{configPath: configPath}
}

// Load reads config from disk or returns defaults
func (m *Manager) Load() *AppConfig {
	m.mu.Lock()
	defer m.mu.Unlock()

	data, err := os.ReadFile(m.configPath)
	if err != nil {
		m.cfg = Default()
		return m.cfg
	}

	cfg := Default()
	if err := json.Unmarshal(data, cfg); err != nil {
		m.cfg = Default()
		return m.cfg
	}
	m.cfg = cfg
	return m.cfg
}

// Get returns the current in-memory config
func (m *Manager) Get() *AppConfig {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.cfg == nil {
		return Default()
	}
	// Return a copy to avoid races
	copy := *m.cfg
	return &copy
}

// Save persists updated config to disk
func (m *Manager) Save(updated *AppConfig) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if err := os.MkdirAll(filepath.Dir(m.configPath), 0755); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}

	data, err := json.MarshalIndent(updated, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}

	if err := os.WriteFile(m.configPath, data, 0600); err != nil {
		return fmt.Errorf("write config: %w", err)
	}

	m.cfg = updated
	return nil
}

// UpdateVPN updates only the VPN portion of config
func (m *Manager) UpdateVPN(vpn VPNConfig) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.cfg == nil {
		m.cfg = Default()
	}
	m.cfg.VPN = vpn
	return m.saveUnlocked()
}

// UpdateProxy updates only the proxy portion of config
func (m *Manager) UpdateProxy(proxy ProxyConfig) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.cfg == nil {
		m.cfg = Default()
	}
	m.cfg.Proxy = proxy
	return m.saveUnlocked()
}

func (m *Manager) saveUnlocked() error {
	if err := os.MkdirAll(filepath.Dir(m.configPath), 0755); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}
	data, err := json.MarshalIndent(m.cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(m.configPath, data, 0600)
}
