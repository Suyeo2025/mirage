#!/bin/bash
set -e

PSK="${1:?Usage: install-client.sh <PSK>}"
SERVER="${2:-sla.sunlawai.com}"
LISTEN="${3:-0.0.0.0:1080}"

echo "=== Mirage Client Install ==="

mkdir -p /opt/mirage

# Copy binary
cp mirage-client /opt/mirage/mirage-client
chmod +x /opt/mirage/mirage-client

# Systemd service
cat > /etc/systemd/system/mirage-client.service << EOF
[Unit]
Description=Mirage Client (SOCKS5)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/opt/mirage/mirage-client --server ${SERVER} --psk ${PSK} --listen ${LISTEN}
Restart=always
RestartSec=3
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF

systemctl stop mirage-client 2>/dev/null || true
systemctl daemon-reload
systemctl enable mirage-client
systemctl start mirage-client

echo "=== Done. Checking status... ==="
sleep 2
systemctl status mirage-client --no-pager
echo ""
echo "Logs: journalctl -u mirage-client -f"
echo ""
echo "SOCKS5 proxy available at ${LISTEN}"
echo "sing-box config: set outbound socks to 127.0.0.1:1080"
