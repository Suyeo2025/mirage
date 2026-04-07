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

### Server

```bash
# REALITY mode (recommended)
mirage-server \
  --domain example.com \
  --psk <pre-shared-key> \
  --reality-dest troncent.com:443 \
  --reality-sni troncent.com \
  --reality-private-key <base64-x25519-private-key> \
  --reality-short-id <hex-short-id> \
  --listen :9445

# Let's Encrypt mode
mirage-server --domain example.com --psk <key> --listen :443

# Custom certificate
mirage-server --domain example.com --psk <key> --cert cert.pem --key key.pem --listen :8444
```

### Client

```bash
# REALITY mode
mirage-client \
  --server <ip>:9445 \
  --psk <pre-shared-key> \
  --reality-public-key <base64-x25519-public-key> \
  --reality-short-id <hex-short-id> \
  --reality-sni troncent.com \
  --listen 0.0.0.0:1090

# Direct TLS mode
mirage-client --server example.com:8444 --psk <key> --listen 127.0.0.1:1080
```

### sing-box Integration

Add as SOCKS5 outbound in sing-box:

```json
{
  "outbounds": [
    {
      "type": "socks",
      "tag": "mirage",
      "server": "127.0.0.1",
      "server_port": 1090
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
    → HTTP/2 Carrier (50ms RTT-quantized flush) → REALITY TLS → Server → TCP relay
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
