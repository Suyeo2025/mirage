# Mirage

Anti-censorship proxy with provable traffic obfuscation, REALITY TLS, and CDN compatibility.

## Features

- **REALITY TLS** — Perfect TLS handshake mimicry via real server certificate (e.g. `troncent.com`)
- **Gaussian Padding** — Truncated Gaussian distribution (CCS 2021), 100x harder to detect than uniform
- **Packet Splitting** — Early packets split into 2-4 random chunks, breaking TLS handshake fingerprints
- **Decoy Streams** — Periodic fake traffic drowns real handshake patterns
- **RTT Quantization** — 50ms fixed flush prevents cross-layer RTT fingerprinting (NDSS 2025)
- **Hot-updatable Config** — Server pushes padding params to clients via `CmdSettings`
- **Flow Control** — Credit-based `CmdWND` prevents silent data drops
- **sing-box Compatible** — SOCKS5 outbound for sing-box selector

## Quick Start

> **Secrets handling**: never put `--psk` (or REALITY private key, outbound
> UUID) on the command line. They leak through `ps`, `/proc/<pid>/cmdline`,
> and `systemctl cat`. Put them in `/etc/mirage/env` (mode `0600`) and let
> the binary read them via the `MIRAGE_PSK` / `MIRAGE_REALITY_PRIVATE_KEY` /
> `MIRAGE_OUTBOUND_UUID` env vars. The systemd templates in `deploy/` already
> wire this up via `EnvironmentFile`.

### `/etc/mirage/env` (server)

```
MIRAGE_PSK=<pre-shared-key>
MIRAGE_REALITY_PRIVATE_KEY=<base64-x25519-private-key>
MIRAGE_OUTBOUND_UUID=<vmess-uuid>           # only if using outbound
```

### `/etc/mirage/env` (client)

```
MIRAGE_PSK=<pre-shared-key>
```

### Server

```bash
# REALITY mode (recommended) — secrets read from /etc/mirage/env
mirage-server \
  --domain example.com \
  --reality-dest troncent.com:443 \
  --reality-sni troncent.com \
  --reality-short-id <hex-short-id> \
  --listen :9445

# With VMess+WS outbound (non-landing, traffic exits via upstream proxy)
mirage-server \
  --domain example.com \
  --reality-dest troncent.com:443 \
  --reality-sni troncent.com \
  --reality-short-id <hex-short-id> \
  --listen :9445 \
  --outbound-server <vmess-host>:<port> \
  --outbound-ws-path /relay

# Let's Encrypt mode
mirage-server --domain example.com --listen :443

# Custom certificate
mirage-server --domain example.com --cert cert.pem --key key.pem --listen :8444
```

### Server policy

By default the server refuses to dial private/bogon IP space (RFC1918, CGNAT,
loopback, link-local, multicast, IPv6 ULA, etc.) — this stops a leaked PSK
from turning the server into an internal-network SSRF jump. Targets are
resolved once and dialed by IP to close the DNS-rebind window.

To allow a specific internal range (e.g. reach a NAS at `192.168.1.10`):

```bash
mirage-server --allow-cidr 192.168.0.0/16,10.0.0.0/8 ...
```

### Client

```bash
# REALITY mode — PSK from /etc/mirage/env
mirage-client \
  --server <ip>:9445 \
  --reality-public-key <base64-x25519-public-key> \
  --reality-short-id <hex-short-id> \
  --reality-sni troncent.com \
  --listen 127.0.0.1:1080

# Direct TLS mode
mirage-client --server example.com:8444 --listen 127.0.0.1:1080
```

> **Listen address**: SOCKS5 has no auth. The default `127.0.0.1:1080` keeps
> the proxy local. Only bind to `0.0.0.0` if you are deliberately exposing it
> to a trusted LAN (e.g. on a router), and firewall the port.

### sing-box Integration

Add as SOCKS5 outbound in sing-box:

```json
{
  "outbounds": [
    {
      "type": "socks",
      "tag": "mirage",
      "server": "127.0.0.1",
      "server_port": 1080
    }
  ]
}
```

Route server IP to direct (bypass tun):

```json
{
  "route": {
    "rules": [
      { "ip_cidr": ["<server-ip>/32"], "outbound": "direct" }
    ]
  }
}
```

## Architecture

```
SOCKS5 Client → Mux (7-byte framing) → Morph Engine (Gaussian padding + split + decoy)
    → HTTP/2 Carrier (50ms RTT-quantized flush) → REALITY TLS → Server → TCP relay / VMess+WS outbound
```

## Security

| Layer | Technique | Reference |
|---|---|---|
| TLS Fingerprint | REALITY / uTLS Chrome | Identical to real browser |
| TLS-in-TLS Defense | Gaussian padding + splitting + decoys | Degabriele CCS 2021; Xue USENIX 2024 |
| RTT Defense | 50ms fixed flush | Xue NDSS 2025 |
| Active Probing | Real website fallback | HTTPT (FOCI 2020) |
| Auth | AES-256-GCM + Argon2id | Per-request replay-proof tokens |

## Build

```bash
make build-all    # All platforms
make test         # Run tests
```

## License

MIT
