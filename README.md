# App Security

Desktop security application for protecting users on public WiFi/LAN networks.

## Features (MVP)

- VPN auto-connect with WireGuard
- Kill Switch (blocks traffic if VPN drops)
- ARP Spoof Detection
- DNS-over-HTTPS
- Firewall Hardening
- Alert System
- MAC Randomization
- DNS Leak Prevention

## Requirements

- Rust 1.75+
- Root/admin privileges for network operations
- pcap library (for packet capture)

## Development

```bash
# Build
cargo build

# Run tests
cargo test

# Run
cargo run
```

## Architecture

See `docs/superpowers/specs/2026-06-19-app-security-design.md`

## License

MIT
