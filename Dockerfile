# ─────────────────────────────────────────────────────────────────────────────
#  Kyle VPN Proxy — Multi-arch (amd64 / arm64) Container
#  Layers:
#    1. node-builder  → Svelte → backend/static/
#    2. go-builder    → Go binary (embeds static/)
#    3. runtime       → gpclient + v2ray + final binary
# ─────────────────────────────────────────────────────────────────────────────

# ── 1. Build Svelte frontend ────────────────────────────────────────────────
FROM node:20-alpine AS node-builder
WORKDIR /app/frontend
COPY frontend/package.json ./
RUN npm install
COPY frontend/ ./
# Output goes directly to backend/static (vite.config outDir)
RUN mkdir -p /app/backend/static && npm run build

# ── 2. Build Go binary ──────────────────────────────────────────────────────
FROM golang:1.22-alpine AS go-builder
WORKDIR /app/backend

# Dependency cache layer
COPY backend/go.mod backend/go.sum ./
RUN go mod download

# Copy source + the compiled static files from node-builder
COPY backend/ ./
COPY --from=node-builder /app/backend/static ./static

# Static binary, no CGO, multi-arch
ARG TARGETARCH
RUN CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH} \
    go build -ldflags="-s -w" -o kyle-proxy .

# ── 3. Runtime image ─────────────────────────────────────────────────────────
FROM debian:bookworm-slim AS runtime

# Install runtime deps:
#   ca-certificates      — TLS verification
#   openconnect          — underlying VPN library used by gpclient
#   iproute2 iptables    — network routing helpers
#   curl unzip           — download v2ray + gpclient binaries
#   procps               — ps/pkill inside container
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        openconnect \
        iproute2 \
        iptables \
        curl \
        unzip \
        procps \
    && rm -rf /var/lib/apt/lists/*

# ── Download v2ray ────────────────────────────────────────────────────────────
# Check latest at: https://github.com/v2fly/v2ray-core/releases
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
    mv /tmp/v2ray/v2ray /usr/local/bin/v2ray; \
    chmod +x /usr/local/bin/v2ray; \
    rm -rf /tmp/v2ray /tmp/v2ray.zip

# ── Download GlobalProtect-openconnect (gpclient + gpauth) ────────────────────
# Check latest at: https://github.com/yuezk/GlobalProtect-openconnect/releases
# The project provides pre-built binaries for x86_64 and aarch64.
ARG GP_VERSION=2.0.1
RUN set -eux; \
    case "${TARGETARCH}" in \
        amd64)  GP_ARCH="x86_64-unknown-linux-musl" ;; \
        arm64)  GP_ARCH="aarch64-unknown-linux-musl" ;; \
        # Fallback for arm/v7: use openconnect CLI directly (no gpclient binary)
        arm)    echo "arm/v7: using openconnect directly, no gpclient binary" && exit 0 ;; \
        *)      echo "Unsupported arch: ${TARGETARCH}" && exit 1 ;; \
    esac; \
    curl -fsSL -o /tmp/gp.tar.gz \
        "https://github.com/yuezk/GlobalProtect-openconnect/releases/download/v${GP_VERSION}/globalprotect-openconnect_${GP_VERSION}_${GP_ARCH}.tar.gz" \
    || { echo "WARNING: gpclient binary not found for ${GP_ARCH} — using openconnect fallback" && exit 0; }; \
    tar -xzf /tmp/gp.tar.gz -C /tmp/gp-extract --strip-components=0 2>/dev/null \
    || tar -xzf /tmp/gp.tar.gz -C /tmp/gp-extract; \
    find /tmp/gp-extract -name "gpclient" -exec mv {} /usr/local/bin/gpclient \; ; \
    find /tmp/gp-extract -name "gpauth"   -exec mv {} /usr/local/bin/gpauth \; ; \
    chmod +x /usr/local/bin/gpclient /usr/local/bin/gpauth 2>/dev/null || true; \
    rm -rf /tmp/gp.tar.gz /tmp/gp-extract

# ── Copy application binary ───────────────────────────────────────────────────
COPY --from=go-builder /app/backend/kyle-proxy /usr/local/bin/kyle-proxy

# ── Copy entrypoint ───────────────────────────────────────────────────────────
COPY scripts/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# ── Data volume (config + custom certs) ──────────────────────────────────────
VOLUME ["/data"]


# ── Ports ─────────────────────────────────────────────────────────────────────
# 8888 = Web management UI  |  8080 = HTTP proxy  |  1080 = SOCKS5
EXPOSE 8888
EXPOSE 8080
EXPOSE 1080
EXPOSE 8388

# ── Capabilities needed for TUN/VPN ──────────────────────────────────────────
# Requires: --cap-add NET_ADMIN  and  --device /dev/net/tun
# See docker-compose.yml

ENTRYPOINT ["/entrypoint.sh"]
