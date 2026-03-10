# ─────────────────────────────────────────────────────────────────────────────
#  Kyle VPN Proxy — Multi-arch (amd64 / arm64) Container
#
#  Build stages (ordered for maximum layer-cache reuse):
#    1. node-builder  — npm ci + vite build  (cache busted by package*.json / src)
#    2. go-builder    — go mod download + go build  (cache busted by go.mod / src)
#    3. downloader    — curl v2ray + gpclient  (cache busted by version ARGs only)
#    4. runtime       — system deps -> versioned bins -> app binary
#
#  Cache strategy:
#    --mount=type=cache  -> speeds up local / self-hosted runner rebuilds
#    In CI: BuildKit registry cache (mode=max) stores all intermediate layers
#           so only truly changed stages re-execute on each push.
# ─────────────────────────────────────────────────────────────────────────────
# syntax=docker/dockerfile:1

# ── 1. Build Svelte frontend ─────────────────────────────────────────────────
FROM node:20-alpine AS node-builder
WORKDIR /app/frontend
# Copy lockfiles first — this layer is cached as long as deps don't change
COPY frontend/package.json frontend/package-lock.json ./
# --mount=type=cache keeps ~/.npm warm between local rebuilds
RUN --mount=type=cache,target=/root/.npm \
    npm ci --prefer-offline
COPY frontend/ ./
RUN npm run build

# ── 2. Build Go binary ───────────────────────────────────────────────────────
FROM golang:1.25-alpine AS go-builder
WORKDIR /app/backend
# go.mod/go.sum first — cached until deps change
COPY backend/go.mod backend/go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download
# Source + compiled frontend (static files embedded in the binary)
COPY backend/ ./
COPY --from=node-builder /app/backend/static ./static
# --mount=type=cache reuses compiled packages across incremental rebuilds
ARG TARGETARCH
RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg/mod \
    CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH} \
    go build -ldflags="-s -w" -o kyle-proxy .

# ── 3. Download external binaries ────────────────────────────────────────────
# Isolated stage: slow network fetches only re-run when version ARGs change,
# not on source-code changes. curl/unzip are NOT carried into the runtime image.
FROM debian:bookworm-slim AS downloader
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl unzip \
    && rm -rf /var/lib/apt/lists/*

# Placeholder files ensure COPY --from=downloader never fails (e.g. arm/v7)
RUN mkdir -p /dl && touch /dl/gpclient /dl/gpauth

# v2ray — https://github.com/v2fly/v2ray-core/releases
ARG V2RAY_VERSION=5.16.1
ARG TARGETARCH
RUN set -eux; \
    case "${TARGETARCH}" in \
        amd64)  V2RAY_ARCH="64" ;; \
        arm64)  V2RAY_ARCH="arm64-v8a" ;; \
        arm)    V2RAY_ARCH="arm32-v7a" ;; \
        *)      echo "Unsupported arch: ${TARGETARCH}" && exit 1 ;; \
    esac; \
    curl -fsSL -o /tmp/v2ray.zip \
        "https://github.com/v2fly/v2ray-core/releases/download/v${V2RAY_VERSION}/v2ray-linux-${V2RAY_ARCH}.zip"; \
    unzip -q /tmp/v2ray.zip -d /tmp/v2ray; \
    install -m755 /tmp/v2ray/v2ray /dl/v2ray; \
    rm -rf /tmp/v2ray /tmp/v2ray.zip

# gpclient + gpauth — https://github.com/yuezk/GlobalProtect-openconnect/releases
ARG GP_VERSION=2.0.1
RUN set -eux; \
    case "${TARGETARCH}" in \
        arm)   echo "arm/v7: no gpclient binary — openconnect fallback" && exit 0 ;; \
        amd64) GP_ARCH="x86_64-unknown-linux-musl" ;; \
        arm64) GP_ARCH="aarch64-unknown-linux-musl" ;; \
        *)     echo "Unsupported arch: ${TARGETARCH}" && exit 1 ;; \
    esac; \
    curl -fsSL -o /tmp/gp.tar.gz \
        "https://github.com/yuezk/GlobalProtect-openconnect/releases/download/v${GP_VERSION}/globalprotect-openconnect_${GP_VERSION}_${GP_ARCH}.tar.gz" \
        || { echo "WARNING: gpclient not available — openconnect fallback" && exit 0; }; \
    mkdir /tmp/gp; \
    tar -xzf /tmp/gp.tar.gz -C /tmp/gp --strip-components=0 2>/dev/null \
        || tar -xzf /tmp/gp.tar.gz -C /tmp/gp; \
    find /tmp/gp -name "gpclient" -exec install -m755 {} /dl/gpclient \; ; \
    find /tmp/gp -name "gpauth"   -exec install -m755 {} /dl/gpauth   \; ; \
    rm -rf /tmp/gp.tar.gz /tmp/gp

# ── 4. Runtime image ──────────────────────────────────────────────────────────
FROM debian:bookworm-slim AS runtime

# System packages — rarely change; first layer for maximum cache stability.
# curl and unzip intentionally absent (downloads handled in the downloader stage).
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        openconnect \
        iproute2 \
        iptables \
        procps \
    && rm -rf /var/lib/apt/lists/*

# Versioned binaries — layer invalidated only when V2RAY_VERSION / GP_VERSION change
COPY --from=downloader /dl/v2ray    /usr/local/bin/v2ray
COPY --from=downloader /dl/gpclient /usr/local/bin/gpclient
COPY --from=downloader /dl/gpauth   /usr/local/bin/gpauth
RUN chmod +x /usr/local/bin/v2ray \
    && chmod +x /usr/local/bin/gpclient /usr/local/bin/gpauth 2>/dev/null || true

# Application binary — changes most frequently; placed last to minimise cache busting
COPY --from=go-builder /app/backend/kyle-proxy /usr/local/bin/kyle-proxy
COPY scripts/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# ── Metadata ──────────────────────────────────────────────────────────────────
VOLUME ["/data"]
# 8888 = Web UI  |  8080 = HTTP proxy  |  1080 = SOCKS5  |  8388 = VMess
EXPOSE 8888 8080 1080 8388
# Requires: --cap-add NET_ADMIN  and  --device /dev/net/tun
ENTRYPOINT ["/entrypoint.sh"]
