#!/bin/bash
# ─────────────────────────────────────────────────────────────────────────────
#  Kyle VPN Proxy — Container Entrypoint
# ─────────────────────────────────────────────────────────────────────────────
set -e

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo " Kyle VPN Proxy"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# ── 1. Install custom CA certificates ────────────────────────────────────────
CERT_DIR="/data/certs"
if [ -d "$CERT_DIR" ]; then
    CERTS=$(find "$CERT_DIR" -name "*.crt" -o -name "*.pem" -o -name "*.cer" 2>/dev/null)
    if [ -n "$CERTS" ]; then
        echo "[CERTS] Installing custom CA certificates…"
        for cert in $CERTS; do
            name=$(basename "$cert" | tr ' ' '_')
            cp "$cert" "/usr/local/share/ca-certificates/${name}.crt" 2>/dev/null || true
        done
        update-ca-certificates --fresh 2>&1 | tail -3
        echo "[CERTS] Done."
    fi
fi

# ── 2. Ensure /dev/net/tun exists ─────────────────────────────────────────────
if [ ! -c /dev/net/tun ]; then
    echo "[TUN] Creating /dev/net/tun device…"
    mkdir -p /dev/net
    mknod /dev/net/tun c 10 200
    chmod 0666 /dev/net/tun
fi

# ── 3. Save original default gateway (before VPN may change routing) ──────────
ORIG_GW=$(ip route show default 2>/dev/null | awk '/default/ {print $3; exit}')
ORIG_DEV=$(ip route show default 2>/dev/null | awk '/default/ {print $5; exit}')

if [ -n "$ORIG_GW" ] && [ -n "$ORIG_DEV" ]; then
    echo "[NET] Original gateway: ${ORIG_GW} via ${ORIG_DEV}"
    # Add a separate routing table (200) that always uses the original gateway.
    # This ensures the management port (8888) stays accessible even when VPN
    # takes over the default route.
    ip rule add fwmark 0x1 table 200 2>/dev/null || true
    ip route add default via "$ORIG_GW" dev "$ORIG_DEV" table 200 2>/dev/null || true

    # Mark packets from management port so they use table 200 (not VPN)
    iptables -t mangle -A OUTPUT -p tcp --sport 8888 -j MARK --set-mark 0x1 2>/dev/null || true
fi

# ── 4. Ensure data directory exists ──────────────────────────────────────────
mkdir -p /data/certs

# ── 5. Start the main application ─────────────────────────────────────────────
echo "[START] Launching kyle-proxy on :8888 …"
exec /usr/local/bin/kyle-proxy "$@"
