# Deployment Guide

This guide deploys GlobalProtect Manager on a Linux Docker host. The container manages one local GlobalProtect VPN profile and exposes only the management UI on TCP port `8888`.

## Requirements

- Docker Engine with the Compose v2 plugin (`docker compose`)
- Linux host with `/dev/net/tun`
- Permission to grant `NET_ADMIN` and `SYS_PTRACE`
- Outbound HTTPS access to the GlobalProtect portal and, when enabled, Telegram
- A persistent Docker volume for `/data`

Verify the host before deployment:

```bash
docker --version
docker compose version
test -c /dev/net/tun && echo "TUN available"
```

## Files and persistent data

The supplied Compose configuration creates the physical volume `globalprotect-manager-data` and mounts it at `/data`.

Important paths:

| Path | Purpose |
|---|---|
| `/data/config.json` | GlobalProtect profile, including the configured password and optional TOTP seed; file mode is `0600` |
| `/data/telegram-access.json` | Telegram pending/approved/denied users; file mode is `0600` |
| `/data/certs/` | Uploaded or mounted CA certificates |

Protect the Docker volume like a credential store. The application configuration contains the GlobalProtect password and optional TOTP seed in plaintext inside the volume. Restrict host and Docker daemon access.

## Deploy with Docker Compose

### 1. Clone and prepare configuration

```bash
git clone https://github.com/zt-hky/kyle-proxy.git
cd kyle-proxy
cp .env.example .env
chmod 600 .env
```

Edit `.env` before starting the service. Telegram can be left disabled initially by keeping both Telegram values empty.

### 2. Validate the resolved configuration

```bash
docker compose config
```

Confirm that:

- service, image, and container are named `globalprotect-manager`
- only `8888:8888` is published
- `/dev/net/tun`, `NET_ADMIN`, and `SYS_PTRACE` are present
- the volume resolves to `globalprotect-manager-data`

### 3. Build and start

```bash
docker compose up -d --build
```

Follow startup and health logs:

```bash
docker compose ps
docker compose logs -f globalprotect-manager
```

The service is ready when the health check is healthy:

```bash
curl -fsS http://localhost:8888/api/health
```

Open the UI at `http://<docker-host>:8888`.

## Deploy with plain Docker

Build the image:

```bash
docker build -t globalprotect-manager:latest .
docker volume create globalprotect-manager-data
```

Run it:

```bash
docker run -d \
  --name globalprotect-manager \
  --restart unless-stopped \
  --stop-timeout 25 \
  --device /dev/net/tun:/dev/net/tun \
  --cap-add NET_ADMIN \
  --cap-add SYS_PTRACE \
  -p 8888:8888 \
  --env-file .env \
  -e CONFIG_PATH=/data/config.json \
  -e LISTEN_ADDR=:8888 \
  -v globalprotect-manager-data:/data \
  globalprotect-manager:latest
```

Check health:

```bash
docker inspect --format '{{.State.Status}}' globalprotect-manager
curl -fsS http://localhost:8888/api/health
```

## First GlobalProtect configuration

1. Open `http://<docker-host>:8888`.
2. Select **Config**.
3. Set the required **Portal** and **Username**.
4. Set **Password** and, when required, an explicit gateway.
5. Choose certificate behavior:
   - upload a private CA certificate, or
   - enable certificate pinning only when you understand and accept the server certificate trust model.
6. Optionally save the base32 TOTP secret. A saved TOTP seed enables generated OTP responses.
7. Enable auto-reconnect only when a saved TOTP seed exists. The service rejects auto-reconnect without it.
8. Save, return to **Dashboard**, and connect.
9. Submit additional OTP challenges from the Web UI or an approved Telegram private chat.

Portal, gateway, credentials, CA settings, and OpenConnect arguments are intentionally configurable only in the Web UI. Telegram controls the existing single profile; it does not create profiles.

## Optional GitHub OAuth protection

Without GitHub OAuth variables, the management UI is unprotected. For a network-accessible deployment, create a GitHub OAuth App and set:

```dotenv
GITHUB_CLIENT_ID=...
GITHUB_CLIENT_SECRET=...
GITHUB_ALLOWED_USERS=alice,bob
AUTH_SECRET=<long-random-value>
PUBLIC_URL=https://vpn-manager.example.com
```

Set the OAuth callback URL to:

```text
https://vpn-manager.example.com/auth/callback
```

Restart after changing environment variables:

```bash
docker compose up -d --force-recreate
```

Use TLS at the reverse proxy when exposing the UI outside a trusted network.

## Operations

```bash
# Status
docker compose ps

# Logs
docker compose logs --tail=200 globalprotect-manager

# Restart
docker compose restart globalprotect-manager

# Stop without deleting data
docker compose down

# Update and rebuild
git pull
docker compose up -d --build
```

## Backup and restore

Create a backup archive without stopping the source volume:

```bash
docker run --rm \
  -v globalprotect-manager-data:/source:ro \
  -v "$PWD":/backup \
  alpine:3.20 tar -C /source -czf /backup/globalprotect-manager-data.tgz .
```

Restore only into an empty destination volume:

```bash
docker volume create globalprotect-manager-data
docker run --rm \
  -v globalprotect-manager-data:/data \
  -v "$PWD":/backup:ro \
  alpine:3.20 tar -C /data -xzf /backup/globalprotect-manager-data.tgz
```

For migration from the previous deployment volume, stop the old service and run:

```bash
make migrate-data OLD_VOLUME=<actual-old-volume-name>
```

The migration target refuses a missing source or non-empty destination, copies hidden files, verifies the copy, and never deletes the source.

## Troubleshooting

### Container cannot create a tunnel

Verify `/dev/net/tun` exists and the container has `NET_ADMIN`:

```bash
docker exec globalprotect-manager test -c /dev/net/tun
docker inspect globalprotect-manager --format '{{json .HostConfig.CapAdd}}'
```

### UI is unreachable after VPN connects

Keep host port `8888` published. The entrypoint preserves the original default gateway and marks responses sourced from port `8888` so management traffic does not follow the full-tunnel route.

### Telegram is disabled but the UI is healthy

This is fail-safe behavior. Check logs for one of:

- both Telegram variables absent: bot intentionally disabled
- only one variable set: both token and owner ID are required
- invalid/non-positive owner ID
- malformed or invalid `/data/telegram-access.json`

Fix the environment or access file, then recreate the container. Never paste the bot token into logs or support messages.
