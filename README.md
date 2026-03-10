# Kyle VPN Proxy

[![Build & Push to GHCR](https://github.com/zt-hky/kyle-proxy/actions/workflows/docker.yml/badge.svg)](https://github.com/zt-hky/kyle-proxy/actions/workflows/docker.yml)

> Single Docker container: GlobalProtect VPN client + HTTP/SOCKS5 proxy + Svelte web UI.  
> Optimised for ARM64 TV boxes (2 GB RAM / 4-core). Works on amd64 too.

---

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                  Docker Container                   │
│                                                     │
│  ┌──────────────┐   ┌───────────────────────────┐  │
│  │  Go backend  │   │  openconnect --protocol=gp│  │
│  │  :8888       │──▶│  GlobalProtect VPN        │  │
│  │  REST API    │   │  → TUN interface (tun0)   │  │
│  │  Svelte UI   │   └───────────────────────────┘  │
│  └──────┬───────┘                                   │
│         │                                           │
│  ┌──────▼───────┐                                   │
│  │  v2ray       │  ← iPhone / any device connects  │
│  │  :8080 HTTP  │  → routes traffic through VPN    │
│  │  :1080 SOCKS5│                                   │
│  └──────────────┘                                   │
└─────────────────────────────────────────────────────┘
          ▲                      ▲
     iPhone proxy            Web browser
    (HTTP / SOCKS5)           (UI :8888)
```

---

## Quick Start

### Pull from GHCR (recommended)

```bash
# Pull latest (multi-arch: amd64 + arm64)
docker pull ghcr.io/zt-hky/kyle-proxy:latest

# Run
docker compose up -d

# Open Web UI
http://<host-ip>:8888
```

### Build locally

```bash
git clone https://github.com/zt-hky/kyle-proxy && cd kyle-proxy

make build-arm64   # build linux/arm64 image
# or
make build-image   # build for host arch
```

---

## Setup Guide

### 1. Configure VPN

Open **http://\<host-ip\>:8888** → **Config** tab:

| Field | Description |
|-------|-------------|
| Portal | VPN portal address (IP or hostname) |
| Gateway | Optional — leave blank to auto-select |
| Username | Your VPN username |
| Password | Your VPN password |
| Skip TLS Check | ✅ Enable if portal uses a self-signed / internal cert |

Click **Save Config**.

### 2. Connect VPN

Go to **Dashboard** tab:
1. Enter **OTP** (if your org uses TOTP/SecurID)
2. Click **Connect**
3. Wait for status to turn **Connected**

### 3. Configure iPhone Proxy

**Settings → Wi-Fi → tap your network → Configure Proxy**

#### Option A — Manual (HTTP)
| Field | Value |
|-------|-------|
| Proxy | Manual |
| Server | `<host-ip>` |
| Port | `8080` |

#### Option B — Auto (PAC) — recommended
| Field | Value |
|-------|-------|
| Proxy | Auto |
| URL | `http://<host-ip>:8888/pac` |

> ℹ️ iPhone must be on the same Wi-Fi network as the machine running Docker.  
> The PAC file can be configured to only route corporate traffic through the proxy.

#### Verify on iPhone

Open Safari → go to `http://httpbin.org/ip` → you should see your **VPN IP**, not your home IP.

---

## Web UI Tabs

| Tab | Description |
|-----|-------------|
| 🏠 Dashboard | VPN status, connect/disconnect, OTP input |
| ⚙️ Config | Portal/gateway/credentials, proxy ports, TLS options |
| 📡 Proxy | Connection info (IP, ports, PAC URL), setup guide |
| 📋 Logs | Live VPN client output |

---

## docker-compose.yml

```yaml
services:
  kyle-proxy:
    image: ghcr.io/zt-hky/kyle-proxy:latest
    container_name: kyle-proxy
    restart: unless-stopped
    ports:
      - "8888:8888"   # Web UI
      - "8080:8080"   # HTTP proxy
      - "1080:1080"   # SOCKS5 proxy
    volumes:
      - kyle-proxy-data:/data
    cap_add:
      - NET_ADMIN
      - SYS_PTRACE
    devices:
      - /dev/net/tun:/dev/net/tun
    sysctls:
      - net.ipv4.ip_forward=1
    deploy:
      resources:
        limits:
          memory: 512M

volumes:
  kyle-proxy-data:
```

---

## API Reference

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/health` | Health check |
| `GET` | `/api/status` | VPN + proxy status |
| `GET` | `/api/config` | Get config |
| `PUT` | `/api/config` | Save config |
| `POST` | `/api/vpn/connect` | Connect — body: `{"otp":"123456"}` |
| `POST` | `/api/vpn/disconnect` | Disconnect |
| `GET` | `/api/logs` | VPN log lines (JSON array) |
| `GET` | `/api/proxy/info` | Proxy host/port/PAC info |
| `POST` | `/api/certs/upload` | Upload CA cert (multipart `cert`) |
| `GET` | `/pac` | PAC file for auto-proxy |

---

## Custom TLS Certificate

If your VPN server uses an internal CA cert:

**Via Web UI:** Config → Custom CA Certificate → Upload `.crt` / `.pem`

**Via volume mount:**
```yaml
volumes:
  - ./certs:/data/certs:ro
```
Certs are installed at container start via `update-ca-certificates`.

**Skip TLS entirely:** Enable **"Skip TLS certificate check"** in Config.  
This auto-fetches the server cert fingerprint and passes `--servercert pin-sha256:...` to openconnect.

---

## Build from Source

```bash
# Prerequisites: Go 1.22+, Node.js 20+, Docker with buildx

make build          # frontend + backend binary (host arch)
make build-image    # Docker image (host arch)
make build-arm64    # Docker image for linux/arm64
make dev            # Dev: Vite :5173 + Go :8888 with hot-reload
```

---

## Docker Requirements

```yaml
cap_add:
  - NET_ADMIN     # create TUN device + manage routes
  - SYS_PTRACE
devices:
  - /dev/net/tun:/dev/net/tun
sysctls:
  - net.ipv4.ip_forward=1
```

---

## Resource Usage (ARM64 TV Box)

| Component | ~Memory |
|-----------|---------|
| Go backend | ~10 MB |
| v2ray | ~20 MB |
| openconnect | ~15 MB |
| **Total** | **~50 MB idle** |

---

## Troubleshooting

**VPN connects but proxy doesn't route corporate traffic:**
```bash
docker exec kyle-proxy ip route        # should show routes via tun0
docker exec kyle-proxy ip addr show tun0  # should be UP with VPN IP
```

**"certificate does not match hostname" error:**
Enable **Skip TLS certificate check** in the Config tab. This uses `--servercert pin-sha256:` fingerprint pinning (openconnect v9+ compatible).

**iPhone can't reach proxy:**
- Ensure iPhone is on the same Wi-Fi as the Docker host
- Check Docker port `8080` is not firewalled: `curl --proxy http://<host-ip>:8080 http://httpbin.org/ip`

**Management UI unreachable after VPN connects (full-tunnel VPN):**
The entrypoint sets up `iptables` routing marks to keep port 8888 reachable via the original gateway. Ensure `NET_ADMIN` cap is set.

**OTP / MFA not working:**
- Enter OTP in the Dashboard field just before clicking Connect (TOTP codes expire in 30s)
- The app waits 1s after sending the password before piping the OTP to openconnect
