# Kyle VPN Proxy

[![Build & Push to GHCR](https://github.com/zt-hky/kyle-proxy/actions/workflows/docker.yml/badge.svg)](https://github.com/zt-hky/kyle-proxy/actions/workflows/docker.yml)

> Single Docker container: GlobalProtect VPN client + HTTP/SOCKS5/VMess proxy + Svelte web UI.  
> User/group management, per-user domain filtering, VMess export for v2box/v2ray.  
> Optimised for ARM64 TV boxes (2 GB RAM / 4-core). Works on amd64 too.

---

## Architecture

```
┌───────────────────────────────────────────────────────────────┐
│                      Docker Container                         │
│                                                               │
│  ┌─────────────────┐   ┌───────────────────────────────────┐ │
│  │  Go backend     │   │  openconnect --protocol=gp        │ │
│  │  :8888 Web UI   │──▶│  GlobalProtect VPN                │ │
│  │  REST API       │   │  → TUN interface (tun0)           │ │
│  └────────┬────────┘   └───────────────────────────────────┘ │
│           │                                                   │
│  ┌────────▼────────┐                                          │
│  │  v2ray          │  ← Connect from any device              │
│  │  :8080  HTTP    │  → routes through VPN                   │
│  │  :1080  SOCKS5  │                                          │
│  │  :8388  VMess   │  ← v2box / v2rayNG / Shadowrocket       │
│  └─────────────────┘                                          │
└───────────────────────────────────────────────────────────────┘
```

---

## Quick Start

### Pull from GHCR (recommended)

```bash
docker pull ghcr.io/zt-hky/kyle-proxy:latest
docker compose up -d
# Open: http://<host-ip>:8888
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
| � Users | Create proxy users, assign groups, export VMess links |
| 📋 Logs | Live VPN client output |

---

## User & Group Management

### What it does

- Create **proxy users** with password + auto-generated token (used as proxy password)
- Assign users to **groups** that define which domains they can access via proxy (regex patterns)
- Users in **no group** → unrestricted (can access any site via proxy)
- Users in **group(s) with patterns** → only matching domains are routed via proxy
- Proxy automatically requires auth when any user exists (HTTP Basic / SOCKS5 password)

### iPhone setup with auth

1. Go to **🔐 Users** tab → create a user
2. Note the **token** shown (this is the proxy password)
3. Configure iPhone:
   - **Settings → Wi-Fi → Configure Proxy → Manual**
   - Server: `<host-ip>`, Port: `8080`
   - Authentication: username + token

### Per-user PAC (Selective proxy)

Each user gets a PAC URL that only routes their allowed domains through the proxy:

```
http://<host-ip>:8888/pac/<username>
```

iPhone setup:
- **Settings → Wi-Fi → Configure Proxy → Auto**
- URL: `http://<host-ip>:8888/pac/<username>`
- iPhone will prompt for proxy credentials → enter username + token

---

## VMess (v2box / v2rayNG / Shadowrocket)

VMess is a v2ray protocol with UUID-based auth, ideal for v2box on iPhone/Android.

### Setup

1. Go to **🔐 Users** tab → click **📲 VMess** next to a user
2. Copy the `vmess://` link
3. In **v2box** (or v2rayNG): **Add Server → Paste link**
4. Connect — traffic routes through the proxy (then through VPN)

Port: **8388** (TCP)

---

## GitHub OAuth (Management UI Protection)

Protect the web UI so only your GitHub account can access it.

### Setup

1. Go to [GitHub → Settings → Developer Settings → OAuth Apps → New OAuth App](https://github.com/settings/applications/new)
2. Set:
   - **Homepage URL**: `http://<your-host>:8888`
   - **Authorization callback URL**: `http://<your-host>:8888/auth/callback`
3. Add to `docker-compose.yml`:

```yaml
environment:
  - GITHUB_CLIENT_ID=your_client_id
  - GITHUB_CLIENT_SECRET=your_client_secret
  - GITHUB_ALLOWED_USERS=your_github_username
  - AUTH_SECRET=some-long-random-string
  - PUBLIC_URL=http://<your-host>:8888   # only needed if behind NAT
```

4. Restart the container — the UI now requires GitHub login.

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
      - "8388:8388"   # VMess (v2box/v2rayNG)
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
| `GET` | `/api/logs` | VPN log lines |
| `GET` | `/api/proxy/info` | Proxy host/port/PAC info |
| `POST` | `/api/certs/upload` | Upload CA cert (multipart `cert`) |
| `GET` | `/api/users` | List proxy users |
| `POST` | `/api/users` | Create user `{"username","password","groups":[]}` |
| `PUT` | `/api/users/{id}` | Update user |
| `DELETE` | `/api/users/{id}` | Delete user |
| `GET` | `/api/users/{id}/vmess` | Get `vmess://` export link |
| `GET` | `/api/groups` | List groups |
| `POST` | `/api/groups` | Create group `{"name","allowed_patterns":[]}` |
| `PUT` | `/api/groups/{id}` | Update group |
| `DELETE` | `/api/groups/{id}` | Delete group |
| `GET` | `/pac` | Global PAC file |
| `GET` | `/pac/{username}` | Per-user PAC file (filtered by group patterns) |
| `GET` | `/api/auth/status` | Auth status (logged_in, login) |
| `GET` | `/auth/login` | Redirect to GitHub OAuth |
| `GET` | `/auth/logout` | Clear session |
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
