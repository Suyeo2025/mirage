#!/bin/bash
set -e

PSK="${1:?Usage: install-server.sh <PSK>}"
DOMAIN="${2:-sla.sunlawai.com}"

echo "=== Mirage Server Install ==="

# Create directories
mkdir -p /opt/mirage/web /opt/mirage/certs

# Copy binary
cp mirage-server /opt/mirage/mirage-server
chmod +x /opt/mirage/mirage-server

# Default website (anti-probe)
cat > /opt/mirage/web/index.html << 'HTMLEOF'
<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>Welcome</title></head>
<body>
<h1>Welcome to our service</h1>
<p>This server provides cloud infrastructure services.</p>
</body>
</html>
HTMLEOF

# Systemd service
cat > /etc/systemd/system/mirage-server.service << EOF
[Unit]
Description=Mirage Server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/opt/mirage/mirage-server --domain ${DOMAIN} --psk ${PSK} --web-root /opt/mirage/web --cert-dir /opt/mirage/certs --listen :443
Restart=always
RestartSec=3
LimitNOFILE=65535
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
EOF

# Stop existing if any
systemctl stop mirage-server 2>/dev/null || true

# Enable and start
systemctl daemon-reload
systemctl enable mirage-server
systemctl start mirage-server

echo "=== Done. Checking status... ==="
sleep 2
systemctl status mirage-server --no-pager
echo ""
echo "Logs: journalctl -u mirage-server -f"
