package proxy

import "encoding/json"

// ─────────────────────────────────────────────────────────────────────────────
//  V2Ray Client Configuration structs
//
//  These types represent the JSON format understood by v2rayNG, v2box, and
//  v2rayN. BuildClientConfig assembles a ready-to-import config from the
//  server connection parameters and the per-user allowed-domain patterns.
// ─────────────────────────────────────────────────────────────────────────────

// ClientConfig is the top-level v2ray client configuration.
type ClientConfig struct {
	Log       clientLog        `json:"log"`
	Inbounds  []v2rayInbound   `json:"inbounds"`  // reuse server-side inbound type
	Outbounds []clientOutbound `json:"outbounds"`
	Routing   clientRouting    `json:"routing"`
}

type clientLog struct {
	LogLevel string `json:"loglevel"`
}

// ── Outbounds ────────────────────────────────────────────────────────────────

// clientOutbound wraps a protocol with optional stream configuration.
type clientOutbound struct {
	Protocol       string                `json:"protocol"`
	Tag            string                `json:"tag"`
	Settings       interface{}           `json:"settings"`
	StreamSettings *clientStreamSettings `json:"streamSettings,omitempty"`
}

// clientVMessSettings is the "settings" block for a VMess outbound.
type clientVMessSettings struct {
	Vnext []clientVNextServer `json:"vnext"`
}

// clientVNextServer describes one upstream VMess server.
type clientVNextServer struct {
	Address string            `json:"address"`
	Port    int               `json:"port"`
	Users   []clientVMessUser `json:"users"`
}

// clientVMessUser holds the per-user auth details on the outbound side.
type clientVMessUser struct {
	ID       string `json:"id"`
	AlterId  int    `json:"alterId"`
	Security string `json:"security"` // "auto" lets the client negotiate
	Email    string `json:"email,omitempty"`
}

// clientStreamSettings controls the transport layer (TCP, WS, gRPC, …).
type clientStreamSettings struct {
	Network string `json:"network"` // "tcp" for plain TCP
}

// ── Routing ──────────────────────────────────────────────────────────────────

// clientRouting is the top-level routing block.
type clientRouting struct {
	DomainStrategy string              `json:"domainStrategy"`
	Rules          []clientRoutingRule `json:"rules"`
}

// clientRoutingRule represents one routing rule.
// At least one of IP, Domain, or Network must be set (v2ray 5.x requirement).
type clientRoutingRule struct {
	Type        string   `json:"type"`              // always "field"
	IP          []string `json:"ip,omitempty"`      // e.g. ["geoip:private"]
	Domain      []string `json:"domain,omitempty"`  // e.g. ["regexp:.*\\.corp\\..*"]
	Network     string   `json:"network,omitempty"` // catch-all: "tcp,udp"
	OutboundTag string   `json:"outboundTag"`
}

// ── Builder ───────────────────────────────────────────────────────────────────

// BuildClientConfig creates a v2ray client config ready for import in
// v2rayNG / v2box / v2rayN.
//
// Split-tunnel behaviour (client-side):
//   - patterns non-empty → only domains matching a "regexp:<pattern>" rule
//     are routed through the VMess proxy; all other traffic goes DIRECT.
//   - patterns empty     → all traffic is routed through the VMess proxy.
//
// Private/LAN addresses are always bypassed regardless of pattern settings.
func BuildClientConfig(uuid, username, serverHost string, serverPort int, patterns []string) ClientConfig {
	sniff := &v2raySniff{Enabled: true, DestOverride: []string{"http", "tls"}}

	// ── Inbounds (local listeners on the client device) ───────────────────
	inbounds := []v2rayInbound{
		{
			Port:     1080,
			Listen:   "127.0.0.1",
			Protocol: "socks",
			Tag:      "socks-in",
			Settings: v2raySocksSettings{Auth: "noauth", UDP: true, IP: "127.0.0.1"},
			Sniffing: sniff,
		},
		{
			Port:     8080,
			Listen:   "127.0.0.1",
			Protocol: "http",
			Tag:      "http-in",
			Settings: v2rayHTTPSettings{AllowTransparent: false, Timeout: 300},
			Sniffing: sniff,
		},
	}

	// ── Outbounds ─────────────────────────────────────────────────────────
	var bh v2rayBlackholeSettings
	bh.Response.Type = "http"

	outbounds := []clientOutbound{
		{
			Protocol: "vmess",
			Tag:      "proxy",
			Settings: clientVMessSettings{
				Vnext: []clientVNextServer{
					{
						Address: serverHost,
						Port:    serverPort,
						Users: []clientVMessUser{
							{
								ID:       uuid,
								AlterId:  0,
								Security: "auto",
								Email:    username + "@kyle-proxy",
							},
						},
					},
				},
			},
			StreamSettings: &clientStreamSettings{Network: "tcp"},
		},
		{
			Protocol: "freedom",
			Tag:      "direct",
			Settings: v2rayFreedomSettings{},
		},
		{
			Protocol: "blackhole",
			Tag:      "block",
			Settings: bh,
		},
	}

	// ── Routing rules ─────────────────────────────────────────────────────
	var rules []clientRoutingRule

	// Private/LAN IPs are always bypassed (no routing loop).
	rules = append(rules, clientRoutingRule{
		Type:        "field",
		IP:          []string{"geoip:private"},
		OutboundTag: "direct",
	})

	if len(patterns) > 0 {
		// Split-tunnel: only allowed domains go through the proxy.
		domains := make([]string, len(patterns))
		for i, p := range patterns {
			domains[i] = "regexp:" + p
		}
		rules = append(rules, clientRoutingRule{
			Type:        "field",
			Domain:      domains,
			OutboundTag: "proxy",
		})
		// Everything else goes direct (NOT through the proxy).
		rules = append(rules, clientRoutingRule{
			Type:        "field",
			Network:     "tcp,udp",
			OutboundTag: "direct",
		})
	} else {
		// No group restrictions: route all traffic through the proxy.
		rules = append(rules, clientRoutingRule{
			Type:        "field",
			Network:     "tcp,udp",
			OutboundTag: "proxy",
		})
	}

	return ClientConfig{
		Log:      clientLog{LogLevel: "warning"},
		Inbounds: inbounds,
		Outbounds: outbounds,
		Routing: clientRouting{
			DomainStrategy: "IPIfNonMatch",
			Rules:          rules,
		},
	}
}

// MarshalClientConfig serialises a ClientConfig to indented JSON bytes.
// The output is ready to be written as a .json file.
func MarshalClientConfig(cfg ClientConfig) ([]byte, error) {
	return json.MarshalIndent(cfg, "", "  ")
}
