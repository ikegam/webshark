# WebShark

🦈 A web-based network analysis tool for real-time packet visualization on Linux gateways.

## Features

- 🚀 **Single static binary**: Rust, web assets embedded, no runtime files needed
- 📊 **Live dashboard**: upload / download / LAN-internal throughput (with 15 minutes of
  server-side history), per-device traffic, apps & services, top remote hosts, packet sizes
- 🕸️ **Communication graph**: force-directed graph of who talks to whom (last 2 minutes)
- 🔍 **Flows & packet log**: sortable 5-tuple flow table with per-flow packet detail, live log, search
- 🏷️ **Names, not just IPs**: hostnames from observed DNS/mDNS answers and TLS SNI / HTTP Host,
  plus active mDNS reverse lookups for LAN devices; devices grouped by MAC (IPv4 + IPv6)
- ⚠️ **Alerts**: port scan, LAN sweep, new device, heavy upload (heuristics)
- 🔧 **Capture filters**: BPF filters validated by dumpcap before they are applied
- 🌗 Light / dark theme, works on mobile

## Requirements

- Linux with `tshark` / `dumpcap` (Wireshark CLI)
- `dumpcap` must be able to capture without root:
  ```bash
  sudo apt install tshark                      # answer "Yes" to non-superuser capture
  sudo dpkg-reconfigure wireshark-common       # if you answered "No"
  sudo usermod -aG wireshark $USER
  ```
- To build: Rust (stable). For a portable binary add the musl target:
  `rustup target add x86_64-unknown-linux-musl`

## Build and Run

```bash
make build            # static binary: target/x86_64-unknown-linux-musl/release/webshark
make test

WEBSHARK_BIND=127.0.0.1:3000 WEBSHARK_IFACE=any ./target/x86_64-unknown-linux-musl/release/webshark
```

Open `http://<WEBSHARK_BIND>/` in a browser.

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `WEBSHARK_BIND` | `127.0.0.1:3000` | Address the web UI listens on. On a gateway use the **LAN** address, never `0.0.0.0`. |
| `WEBSHARK_IFACE` | `any` | Capture interface. On a router, the LAN interface shows per-device traffic before NAT. |
| `RUST_LOG` | – | Log level (`info`, `debug`, …). |

The UI's own port is always excluded from capture.

## Deploy to a gateway (systemd)

```bash
make deploy                                   # defaults: HOST=192.168.0.1 IFACE=enp3s0 LAN_IFACE=enp3s0
make deploy HOST=10.0.0.1 IFACE=eth1 LAN_IFACE=eth1
make status | make logs | make undeploy
```

`make deploy` runs the tests, builds the static binary, copies it over SSH and installs
`webshark.service` running as an unprivileged `webshark` user (member of `wireshark`),
writes `/etc/default/webshark`, and opens the port with ufw **on the LAN interface only**.

Resource use is bounded for 24/7 operation: packets are piped from dumpcap to tshark (no
capture files on disk), tshark's dissection state is reset periodically, all in-memory tables
are capped, and the service has `MemoryMax=512M`.

## Development

```bash
RUST_LOG=debug cargo run
cargo fmt -- --check
```

## Security Notes

- No root needed: capture privileges come from `dumpcap`'s file capabilities
- There is no authentication: bind to a trusted interface and restrict access with the firewall
- Cross-origin WebSocket connections are rejected
- Consider privacy when monitoring network traffic

## License

BSD 4-Clause License

## Contributing

Please submit bug reports and feature requests via GitHub Issues.
