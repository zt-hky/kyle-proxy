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
	mu     sync.RWMutex
	cmd    *exec.Cmd
	config Config
	err    string
}

// NewManager creates a new proxy manager
func NewManager(cfg Config) *Manager {
	if cfg.HTTPPort == 0 {
		cfg.HTTPPort = 8080
	}
	if cfg.Socks5Port == 0 {
		cfg.Socks5Port = 1080
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
	m.mu.Lock()
	m.config = cfg
	m.mu.Unlock()
	return m.Restart()
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
	cfg := buildV2RayConfig(m.config.HTTPPort, m.config.Socks5Port)
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(v2rayConfigPath, data, 0644)
}

// v2rayConfig is the full JSON structure for v2ray
type v2rayConfig struct {
	Log       v2rayLog        `json:"log"`
	Inbounds  []v2rayInbound  `json:"inbounds"`
	Outbounds []v2rayOutbound `json:"outbounds"`
	DNS       v2rayDNS        `json:"dns"`
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

type v2rayHTTPSettings struct {
	AllowTransparent bool `json:"allowTransparent"`
	Timeout          int  `json:"timeout"`
}

type v2raySocksSettings struct {
	Auth string `json:"auth"`
	UDP  bool   `json:"udp"`
	IP   string `json:"ip"`
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

type v2rayDNS struct {
	Servers []string `json:"servers"`
}

// buildV2RayConfig creates a v2ray config with HTTP + SOCKS5 inbounds and freedom outbound.
// Traffic will flow through the container's routing table — when VPN is active,
// all outbound connections automatically traverse the VPN tunnel.
func buildV2RayConfig(httpPort, socks5Port int) v2rayConfig {
	return v2rayConfig{
		Log: v2rayLog{LogLevel: "warning"},
		Inbounds: []v2rayInbound{
			{
				Port:     httpPort,
				Listen:   "0.0.0.0",
				Protocol: "http",
				Tag:      "http-in",
				Settings: v2rayHTTPSettings{
					AllowTransparent: false,
					Timeout:          300,
				},
				Sniffing: v2raySniff{
					Enabled:      true,
					DestOverride: []string{"http", "tls"},
				},
			},
			{
				Port:     socks5Port,
				Listen:   "0.0.0.0",
				Protocol: "socks",
				Tag:      "socks-in",
				Settings: v2raySocksSettings{
					Auth: "noauth",
					UDP:  true,
					IP:   "0.0.0.0",
				},
				Sniffing: v2raySniff{
					Enabled:      true,
					DestOverride: []string{"http", "tls"},
				},
			},
		},
		Outbounds: []v2rayOutbound{
			{
				Protocol: "freedom",
				Tag:      "direct",
				Settings: v2rayFreedomSettings{},
			},
		},
		DNS: v2rayDNS{
			Servers: []string{"8.8.8.8", "1.1.1.1", "localhost"},
		},
	}
}
