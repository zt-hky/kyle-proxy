# GlobalProtect Manager

A Dockerized GlobalProtect VPN manager with a Svelte web UI and optional Telegram control bot.

## Build

```bash
make build
```

## Run

The default Compose file pulls the multi-architecture image from GitHub Container Registry:

```bash
docker compose pull
docker compose up -d
```

Open `http://<host>:8888`.

The container requires `/dev/net/tun`, `NET_ADMIN`, and `SYS_PTRACE`. Persistent configuration and certificates are stored in the `globalprotect-manager-data` volume.
## Deployment documentation

- [Docker and Docker Compose deployment](docs/deployment.md)
- [Telegram bot setup, owner initialization, and access approval](docs/telegram.md)
- Copy [`.env.example`](.env.example) to `.env` before enabling Telegram or GitHub OAuth.

The deployment guide covers first GlobalProtect profile configuration, persistent-volume backup/restore, migration, health checks, and troubleshooting.

## Telegram

Set `TELEGRAM_BOT_TOKEN` and a positive numeric `TELEGRAM_OWNER_ID`. Optional access-store location:

```text
TELEGRAM_ACCESS_PATH=/data/telegram-access.json
```

The owner approves additional private-chat users through the bot. The bot is disabled when configuration is missing or invalid; the Web UI and local VPN remain available.

## Migration

To copy data from an existing deployment without deleting the source volume:

```bash
make migrate-data OLD_VOLUME=<old-volume-name>
```

The destination must be empty or absent.

## API

- `GET /api/health`
- `GET /api/status`
- `GET /api/config`
- `PUT /api/config`
- `POST /api/vpn/connect`
- `POST /api/vpn/otp`
- `POST /api/vpn/disconnect`
- `GET /api/logs`
- `POST /api/certs/upload`
