package control

import (
	"fmt"
	"strings"

	"globalprotect-manager/internal/config"
	"globalprotect-manager/internal/vpn"
)

type ConnectOptions struct {
	OTP           string
	OTP2          string
	AutoReconnect *bool
}

type manager interface {
	Connect(vpn.ConnectRequest) error
	SubmitOTP(string) error
	Disconnect() error
	GetStatus() vpn.Status
	GetLogs() []string
	OnEvent(func(vpn.Event))
}

type VPN struct {
	manager manager
	config  *config.Manager
}

func NewVPN(manager *vpn.Manager, config *config.Manager) *VPN {
	return &VPN{manager: manager, config: config}
}

func (c *VPN) Connect(options ConnectOptions) error {
	cfg := c.config.Get()
	if strings.TrimSpace(cfg.VPN.Portal) == "" || strings.TrimSpace(cfg.VPN.Username) == "" {
		return fmt.Errorf("VPN portal and username must be configured first")
	}
	autoReconnect := cfg.VPN.AutoReconnect
	if options.AutoReconnect != nil {
		autoReconnect = *options.AutoReconnect
	}
	if autoReconnect && strings.TrimSpace(cfg.VPN.OTPSecret) == "" {
		return fmt.Errorf("auto reconnect requires a saved OTP secret")
	}
	return c.manager.Connect(vpn.ConnectRequest{
		Portal: cfg.VPN.Portal, Gateway: cfg.VPN.Gateway, Username: cfg.VPN.Username,
		Password: cfg.VPN.Password, OTP: options.OTP, OTP2: options.OTP2,
		OTPSecret: cfg.VPN.OTPSecret, AutoReconnect: autoReconnect,
		CertFile: cfg.VPN.CertFile, TrustCert: cfg.VPN.TrustCert,
		ExtraArgs: append([]string(nil), cfg.VPN.ExtraArgs...),
	})
}

func (c *VPN) SubmitOTP(otp string) error { return c.manager.SubmitOTP(otp) }
func (c *VPN) Disconnect() error          { return c.manager.Disconnect() }
func (c *VPN) Status() vpn.Status         { return c.manager.GetStatus() }
func (c *VPN) Logs() []string             { return c.manager.GetLogs() }
func (c *VPN) OnEvent(fn func(vpn.Event)) { c.manager.OnEvent(fn) }

func (c *VPN) HasSavedOTP() bool {
	return strings.TrimSpace(c.config.Get().VPN.OTPSecret) != ""
}
