# Mirage

A next-generation anti-censorship proxy protocol built on **Turbo Tunnel** architecture. Traffic is indistinguishable from normal HTTPS to a CDN — because it IS normal HTTPS to a CDN.

## Key Features

- **Turbo Tunnel**: Inner QUIC session survives transport disruption, connection rotation, and carrier switching — no session loss, ever
- **Cloudflare CDN**: Traffic routes through CDN edge servers. Censor sees Cloudflare IP + Cloudflare TLS certificate + standard HTTPS
- **uTLS Chrome**: Client TLS fingerprint matches Chrome browser (JA3/JA4)
- **Connection Rotation**: Automatic carrier rotation with 2MB data budget + 60-180s lifetime
- **Continuous Morphing**: Exponential-decay padding that smoothly fades from high-stealth to high-performance — no detectable phase transition
- **Video Streaming Disguise**: Downstream responses use `Content-Type: video/mp4` — the most common CDN traffic type
- **Active Probe Defense**: Unauthenticated requests get a real website (HTML pages, JSON API errors, proper 404s)
- **AES-256-GCM Auth**: Per-request tokens with replay prevention

## Architecture

```
Client (SOCKS5)
  → Inner QUIC Session (userspace, persistent)
    → QUIC packets serialized into HTTP/2 POST/GET bodies
      → HTTPS through Cloudflare CDN
        → Origin Server
          → Destination
```

The inner QUIC session runs entirely in memory. QUIC packets are carried as HTTP request/response bodies through the CDN. The CDN terminates TLS and TCP, so the censor cannot see TLS fingerprints, measure RTT discrepancies, or detect nested TLS handshakes.

## Quick Start

### Prerequisites

- Go 1.24+
- A domain with Cloudflare DNS (free plan works)
- A VPS for the origin server

### 1. Build

```bash
git clone https://github.com/houden/mirage.git
cd mirage

# Build for current platform
make build

# Or cross-compile for all platforms
make build-all
```

### 2. Server Setup

**a) DNS**: Point your domain (e.g. `proxy.example.com`) to your VPS IP in Cloudflare, with **Proxy enabled** (orange cloud). Set SSL/TLS mode to **Full (strict)**.

**b) Deploy server**:

```bash
# Copy binary to server
scp bin/mirage-server-linux-amd64 root@your-server:/opt/mirage/mirage-server

# Create web root
ssh root@your-server "mkdir -p /opt/mirage/web /opt/mirage/certs"
scp web/index.html root@your-server:/opt/mirage/web/

# Start (first run will auto-obtain Let's Encrypt certificate)
ssh root@your-server "/opt/mirage/mirage-server \
  --domain proxy.example.com \
  --psk 'your-secret-key' \
  --web-root /opt/mirage/web \
  --cert-dir /opt/mirage/certs"
```

**c) systemd service** (recommended):

```ini
# /etc/systemd/system/mirage.service
[Unit]
Description=Mirage Proxy Server
After=network.target

[Service]
Type=simple
ExecStart=/opt/mirage/mirage-server \
  --domain proxy.example.com \
  --psk "your-secret-key" \
  --web-root /opt/mirage/web \
  --cert-dir /opt/mirage/certs
Restart=always
RestartSec=3
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
```

```bash
systemctl daemon-reload && systemctl enable mirage && systemctl start mirage
```

### 3. Client Setup

```bash
# Run client
./mirage-client \
  --server proxy.example.com \
  --psk "your-secret-key" \
  --listen 127.0.0.1:1080
```

Then configure your browser/system to use SOCKS5 proxy at `127.0.0.1:1080`.

### 4. sing-box Integration

Add Mirage as a SOCKS5 outbound in your sing-box config:

```json
{
  "outbounds": [
    {
      "type": "selector",
      "tag": "proxy",
      "outbounds": ["mirage", "other-node"]
    },
    {
      "type": "socks",
      "tag": "mirage",
      "server": "127.0.0.1",
      "server_port": 1080
    }
  ],
  "route": {
    "rules": [
      {
        "domain": ["proxy.example.com"],
        "action": "route",
        "outbound": "direct"
      }
    ]
  }
}
```

> **Important**: Add a route rule to send `proxy.example.com` traffic directly — otherwise sing-box's TUN creates a routing loop.

### 5. OpenWrt / ImmortalWrt

```bash
# Copy ARM64 binary
cat bin/mirage-client-linux-arm64 | ssh root@router "cat > /tmp/mirage-client && chmod +x /tmp/mirage-client"

# Create init.d service
ssh root@router 'cat > /etc/init.d/mirage << "EOF"
#!/bin/sh /etc/rc.common
START=99
STOP=10
USE_PROCD=1
start_service() {
    procd_open_instance
    procd_set_param command /tmp/mirage-client \
        --server proxy.example.com \
        --psk "your-secret-key" \
        --listen 0.0.0.0:1080
    procd_set_param respawn 5 3 0
    procd_set_param stderr 1
    procd_close_instance
}
EOF
chmod +x /etc/init.d/mirage
/etc/init.d/mirage enable
/etc/init.d/mirage start'
```

## Server Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--domain` | (required) | TLS domain for Let's Encrypt |
| `--psk` | (required) | Pre-shared key for authentication |
| `--web-root` | `./web` | Static website directory |
| `--cert-dir` | `/opt/mirage/certs` | Let's Encrypt certificate cache |
| `--listen` | `:443` | Listen address |

## Client Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--server` | (required) | Server domain (e.g. `proxy.example.com`) |
| `--psk` | (required) | Pre-shared key (must match server) |
| `--listen` | `127.0.0.1:1080` | SOCKS5 listen address |

## Security Properties

| Detection Layer | Defense | Status |
|----------------|---------|--------|
| SNI / IP | Cloudflare CDN IP + CDN certificate | Immune |
| TLS fingerprint | uTLS Chrome + Cloudflare TLS stack | Immune |
| Active probing | Real website + JSON API errors + 404 | Immune |
| Data volume policing | 2MB budget + automatic rotation | Immune |
| TLS-in-TLS | QUIC packets in HTTP body (3 layers deep) | Immune |
| Cross-layer RTT | CDN terminates both TCP and TLS | Immune |
| Traffic pattern ML | Continuous-decay morphing + keepalive | Resistant |

## How It Works

1. Client creates an in-memory QUIC session (no real UDP packets on the wire)
2. QUIC packets are serialized and sent as HTTP/2 POST request bodies to the CDN
3. Server receives HTTP requests, extracts QUIC packets, feeds them to its QUIC session
4. Server sends QUIC response packets back as chunked HTTP responses (`video/mp4`)
5. If a carrier connection dies or rotates, the inner QUIC session retransmits automatically
6. The CDN (Cloudflare) handles TLS termination — censor only sees CDN traffic

## License

MIT
