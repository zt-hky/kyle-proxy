package proxy

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"sync"
	"time"
)

const v2rayConfigPath = "/tmp/v2ray-config.json"

// Config holds v2ray proxy settings
type Config struct {
	HTTPPort   int `json:"http_port"`
	Socks5Port int `json:"socks5_port"`
	VMessPort  int `json:"vmess_port"` // VMess inbound for v2box/v2ray clients
}

// UserAccount is the proxy-manager view of a proxy user (no bcrypt details).
type UserAccount struct {
	Username  string
	Token     string   // plaintext proxy password
	VMessUUID string   // UUID for VMess inbound
	Patterns  []string // nil = allow all; else regex domain patterns
}

// Status represents the proxy service state
type Status struct {
	Running    bool   `json:"running"`
	HTTPPort   int    `json:"http_port"`
	Socks5Port int    `json:"socks5_port"`
	Error      string `json:"error,omitempty"`
}

// Manager manages the v2ray proxy lifecycle
type Manager struct {
	mu       sync.RWMutex
	cmd      *exec.Cmd
	config   Config
	accounts []UserAccount
	err      string
}

// NewManager creates a new proxy manager
func NewManager(cfg Config) *Manager {
	if cfg.HTTPPort == 0 {
		cfg.HTTPPort = 8080
	}
	if cfg.Socks5Port == 0 {
		cfg.Socks5Port = 1080
	}
	if cfg.VMessPort == 0 {
		cfg.VMessPort = 8388
	}
	return &Manager{config: cfg}
}

// Start writes the v2ray config and launches the process
func (m *Manager) Start() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.cmd != nil && m.cmd.Process != nil {
		return nil // already running
	}

	if err := m.writeConfig(); err != nil {
		m.err = err.Error()
		return fmt.Errorf("write v2ray config: %w", err)
	}

	cmd := exec.Command("v2ray", "run", "-c", v2rayConfigPath)
	cmd.Env = os.Environ()

	stdout, _ := cmd.StdoutPipe()
	stderr, _ := cmd.StderrPipe()

	if err := cmd.Start(); err != nil {
		m.err = err.Error()
		return fmt.Errorf("start v2ray: %w", err)
	}

	m.cmd = cmd
	m.err = ""
	log.Printf("[PROXY] v2ray started (HTTP:%d SOCKS5:%d)", m.config.HTTPPort, m.config.Socks5Port)

	// Stream output and auto-restart on exit
	go m.streamOutput(stdout, "out")
	go m.streamOutput(stderr, "err")
	go m.watchProcess()

	return nil
}

// Stop terminates v2ray
func (m *Manager) Stop() {
	m.mu.Lock()
	cmd := m.cmd
	m.cmd = nil
	m.mu.Unlock()

	if cmd != nil && cmd.Process != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		log.Println("[PROXY] v2ray stopped")
	}
}

// Restart stops and starts v2ray (used after config change)
func (m *Manager) Restart() error {
	m.Stop()
	time.Sleep(500 * time.Millisecond)
	return m.Start()
}

// UpdateConfig updates ports and restarts v2ray
func (m *Manager) UpdateConfig(cfg Config) error {
	if cfg.HTTPPort == 0 {
		cfg.HTTPPort = 8080
	}
	if cfg.Socks5Port == 0 {
		cfg.Socks5Port = 1080
	}
	if cfg.VMessPort == 0 {
		cfg.VMessPort = 8388
	}
	m.mu.Lock()
	m.config = cfg
	m.mu.Unlock()
	return m.Restart()
}

// SetAccountsSilent updates accounts without triggering a restart (call before Start).
func (m *Manager) SetAccountsSilent(accounts []UserAccount) {
	m.mu.Lock()
	m.accounts = accounts
	m.mu.Unlock()
}

// SetAccounts updates proxy user accounts and restarts v2ray to apply changes.
func (m *Manager) SetAccounts(accounts []UserAccount) error {
	m.mu.Lock()
	m.accounts = accounts
	m.mu.Unlock()
	return m.Restart()
}

// GetAccounts returns a copy of the current user accounts.
func (m *Manager) GetAccounts() []UserAccount {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]UserAccount, len(m.accounts))
	copy(out, m.accounts)
	return out
}

// GetVMessPort returns the configured VMess inbound port.
func (m *Manager) GetVMessPort() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.config.VMessPort
}

// GetStatus returns the current proxy status
func (m *Manager) GetStatus() Status {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return Status{
		Running:    m.cmd != nil && m.cmd.Process != nil,
		HTTPPort:   m.config.HTTPPort,
		Socks5Port: m.config.Socks5Port,
		Error:      m.err,
	}
}

// watchProcess restarts v2ray if it crashes unexpectedly
func (m *Manager) watchProcess() {
	m.mu.RLock()
	cmd := m.cmd
	m.mu.RUnlock()

	if cmd == nil {
		return
	}

	if err := cmd.Wait(); err != nil {
		m.mu.Lock()
		if m.cmd == cmd { // we didn't intentionally stop it
			m.cmd = nil
			m.err = fmt.Sprintf("v2ray crashed: %v", err)
			m.mu.Unlock()
			log.Printf("[PROXY] v2ray crashed: %v — restarting in 5s", err)
			time.Sleep(5 * time.Second)
			if startErr := m.Start(); startErr != nil {
				log.Printf("[PROXY] failed to restart v2ray: %v", startErr)
			}
		} else {
			m.mu.Unlock()
		}
	}
}

// streamOutput logs v2ray output
func (m *Manager) streamOutput(r io.Reader, label string) {
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		log.Printf("[v2ray/%s] %s", label, scanner.Text())
	}
}

// writeConfig generates and writes the v2ray JSON config
func (m *Manager) writeConfig() error {
	cfg := buildV2RayConfig(m.config, m.accounts)
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(v2rayConfigPath, data, 0600) // 0600: contains proxy passwords
}

// v2rayConfig is the full JSON structure for v2ray
type v2rayConfig struct {
	Log       v2rayLog        `json:"log"`
	Inbounds  []v2rayInbound  `json:"inbounds"`
	Outbounds []v2rayOutbound `json:"outbounds"`
	DNS       v2rayDNS        `json:"dns"`
	Routing   *v2rayRouting   `json:"routing,omitempty"`
}

type v2rayLog struct {
	LogLevel string `json:"loglevel"`
}

type v2rayInbound struct {
	Port     int         `json:"port"`
	Listen   string      `json:"listen"`
	Protocol string      `json:"protocol"`
	Tag      string      `json:"tag"`
	Settings interface{} `json:"settings"`
	Sniffing v2raySniff  `json:"sniffing,omitempty"`
}

// HTTP inbound settings (no auth)
type v2rayHTTPSettings struct {
	AllowTransparent bool `json:"allowTransparent"`
	Timeout          int  `json:"timeout"`
}

// HTTP inbound settings with basic auth accounts
type v2rayHTTPSettingsAuth struct {
	AllowTransparent bool           `json:"allowTransparent"`
	Timeout          int            `json:"timeout"`
	Accounts         []v2rayAccount `json:"accounts"`
}

// SOCKS5 inbound settings (no auth)
type v2raySocksSettings struct {
	Auth string `json:"auth"`
	UDP  bool   `json:"udp"`
	IP   string `json:"ip"`
}

// SOCKS5 inbound settings with password auth
type v2raySocksSettingsAuth struct {
	Auth     string         `json:"auth"`
	UDP      bool           `json:"udp"`
	IP       string         `json:"ip"`
	Accounts []v2rayAccount `json:"accounts"`
}

// VMess inbound settings
type v2rayVMessSettings struct {
	Clients []v2rayVMessClient `json:"clients"`
}

type v2rayVMessClient struct {
	ID      string `json:"id"`
	Email   string `json:"email"` // used in routing rules
	AlterId int    `json:"alterId"`
}

type v2rayAccount struct {
	User string `json:"user"`
	Pass string `json:"pass"`
}

type v2raySniff struct {
	Enabled      bool     `json:"enabled"`
	DestOverride []string `json:"destOverride"`
}

type v2rayOutbound struct {
	Protocol string      `json:"protocol"`
	Tag      string      `json:"tag"`
	Settings interface{} `json:"settings"`
}

type v2rayFreedomSettings struct{}
type v2rayBlackholeSettings struct {
	Response struct {
		Type string `json:"type"`
	} `json:"response"`
}

// Routing
type v2rayRouting struct {
	DomainStrategy string      `json:"domainStrategy"`
	Rules          []v2rayRule `json:"rules"`
}

type v2rayRule struct {
	Type        string   `json:"type"`
	User        []string `json:"user,omitempty"`
	Domain      []string `json:"domain,omitempty"`
	OutboundTag string   `json:"outboundTag"`
}

type v2rayDNS struct {
	Servers []string `json:"servers"`
}

// buildV2RayConfig generates the v2ray config.
//
// When accounts is non-empty:
//   - HTTP and SOCKS5 inbounds require username + token auth
//   - VMess inbound is populated with all user UUIDs
//   - Routing rules enforce per-user domain patterns:
//     users WITH groups → allow group patterns → block everything else
//     users WITHOUT groups → allow all
//
// When accounts is empty → backward-compat open proxy (no auth).
func buildV2RayConfig(cfg Config, accounts []UserAccount) v2rayConfig {
	sniff := v2raySniff{Enabled: true, DestOverride: []string{"http", "tls"}}

	var httpSettings interface{}
	var socksSettings interface{}

	outbounds := []v2rayOutbound{
		{Protocol: "freedom", Tag: "direct", Settings: v2rayFreedomSettings{}},
	}

	var routing *v2rayRouting

	if len(accounts) == 0 {
		// no auth mode
		httpSettings = v2rayHTTPSettings{AllowTransparent: false, Timeout: 300}
		socksSettings = v2raySocksSettings{Auth: "noauth", UDP: true, IP: "0.0.0.0"}
	} else {
		// auth mode: HTTP basic + SOCKS5 password
		accs := make([]v2rayAccount, 0, len(accounts))
		for _, a := range accounts {
			accs = append(accs, v2rayAccount{User: a.Username, Pass: a.Token})
		}
		httpSettings = v2rayHTTPSettingsAuth{AllowTransparent: false, Timeout: 300, Accounts: accs}
		socksSettings = v2raySocksSettingsAuth{Auth: "password", UDP: false, IP: "0.0.0.0", Accounts: accs}

		// Blackhole outbound for blocked traffic
		var bh v2rayBlackholeSettings
		bh.Response.Type = "http"
		outbounds = append(outbounds, v2rayOutbound{Protocol: "blackhole", Tag: "block", Settings: bh})

		// Build routing rules per user
		var rules []v2rayRule
		for _, a := range accounts {
			if len(a.Patterns) > 0 {
				// domain-prefixed patterns for v2ray regexp matching
				domains := make([]string, len(a.Patterns))
				for i, p := range a.Patterns {
					domains[i] = "regexp:" + p
				}
				// allow matched patterns
				rules = append(rules, v2rayRule{
					Type:        "field",
					User:        []string{a.Username},
					Domain:      domains,
					OutboundTag: "direct",
				})
				// block everything else for this user
				rules = append(rules, v2rayRule{
					Type:        "field",
					User:        []string{a.Username},
					OutboundTag: "block",
				})
			} else {
				// no restriction: allow all
				rules = append(rules, v2rayRule{
					Type:        "field",
					User:        []string{a.Username},
					OutboundTag: "direct",
				})
			}
		}
		// default rule: block unauthenticated
		rules = append(rules, v2rayRule{Type: "field", OutboundTag: "block"})
		routing = &v2rayRouting{DomainStrategy: "AsIs", Rules: rules}
	}

	// VMess inbound (always enabled)
	vmessClients := make([]v2rayVMessClient, 0, len(accounts))
	for _, a := range accounts {
		vmessClients = append(vmessClients, v2rayVMessClient{
			ID:      a.VMessUUID,
			Email:   a.Username + "@kyle-proxy",
			AlterId: 0,
		})
	}
	// add a default VMess client if no users configured (for backward compat)
	if len(vmessClients) == 0 {
		vmessClients = append(vmessClients, v2rayVMessClient{
			ID:      "00000000-0000-0000-0000-000000000000",
			Email:   "default@kyle-proxy",
			AlterId: 0,
		})
	}

	return v2rayConfig{
		Log: v2rayLog{LogLevel: "warning"},
		Inbounds: []v2rayInbound{
			{Port: cfg.HTTPPort, Listen: "0.0.0.0", Protocol: "http", Tag: "http-in",
				Settings: httpSettings, Sniffing: sniff},
			{Port: cfg.Socks5Port, Listen: "0.0.0.0", Protocol: "socks", Tag: "socks-in",
				Settings: socksSettings, Sniffing: sniff},
			{Port: cfg.VMessPort, Listen: "0.0.0.0", Protocol: "vmess", Tag: "vmess-in",
				Settings: v2rayVMessSettings{Clients: vmessClients}},
		},
		Outbounds: outbounds,
		DNS:       v2rayDNS{Servers: []string{"8.8.8.8", "1.1.1.1", "localhost"}},
		Routing:   routing,
	}
}
