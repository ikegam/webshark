# webshark

[![Rust](https://github.com/ikegam/webshark/actions/workflows/rust.yml/badge.svg)](https://github.com/ikegam/webshark/actions/workflows/rust.yml)
[![License: BSD-4-Clause](https://img.shields.io/badge/license-BSD--4--Clause-blue.svg)](LICENSE)

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
- To build: Rust 1.85 or newer (edition 2024). For a portable binary add the musl target:
  `rustup target add x86_64-unknown-linux-musl`

## Build and Run

```bash
make build            # static binary: target/x86_64-unknown-linux-musl/release/webshark
make test

WEBSHARK_BIND=127.0.0.1:3000 WEBSHARK_IFACE=eth0 ./target/x86_64-unknown-linux-musl/release/webshark
```

Open `http://<WEBSHARK_BIND>/` in a browser.

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `WEBSHARK_BIND` | `127.0.0.1:3000` | Address (`IP:port`) the web UI listens on. On a gateway use the **LAN** address, never `0.0.0.0`. |
| `WEBSHARK_IFACE` | first LAN interface | Capture interface. The LAN interface shows per-device traffic before NAT. Avoid `any` on a router: forwarded packets are seen twice (LAN and WAN side), doubling all figures. |
| `WEBSHARK_ALLOWED_HOSTS` | – | Extra host names the UI may be reached by (comma separated). Requests with any other `Host` header are rejected (DNS-rebinding protection); the bind address, the machine's hostname (`.local` too) and `localhost` are always allowed. |
| `RUST_LOG` | – | Log level (`info`, `debug`, …). |

The UI's own port is always excluded from capture.

## Deploy to a gateway (systemd)

webshark is meant to be run **only while debugging**, not as an always-on
monitor: `make deploy` installs it but does not enable or start it.

```bash
make deploy                                   # defaults: HOST=192.168.0.1 IFACE=enp3s0 LAN_IFACE=enp3s0
make start                                    # start a debugging session (stops by itself after 2 h)
make start DURATION=30min
make stop                                     # stop now
make status | make logs | make data | make undeploy
```

On the gateway itself the same is available as `sudo webshark-ctl start [DURATION]`,
`sudo webshark-ctl stop` and `webshark-ctl status`.

- `make deploy` runs the tests, builds the static binary, copies it over SSH and installs
  `webshark.service` (unprivileged `webshark` user in the `wireshark` group, not enabled at
  boot), `/etc/default/webshark`, `webshark-ctl`, and the monthly data update timer.
  If a session is running, it is restarted with the new build.
- `webshark-ctl start` opens the UI port with ufw **on the LAN interface only** and arms a
  transient systemd timer that stops webshark after `DURATION`; `stop` closes the port again.
- Captured data is kept in memory only and is discarded when webshark stops.

Resource use is bounded: packets are piped from dumpcap to tshark (no capture files on
disk), tshark's dissection state is reset periodically, all in-memory tables are capped,
and the service has `MemoryMax=512M`.

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

webshark is released under the [BSD 4-Clause License](LICENSE).

### Third-party components

These are not bundled in the repository; they are loaded or downloaded at run time.

| Component | Used for | License |
|---|---|---|
| [DB-IP IP to City Lite](https://db-ip.com/db/download/ip-to-city-lite) | GeoIP map (downloaded by `make data`) | [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/) — "IP Geolocation by DB-IP" is shown on the map |
| [IEEE OUI registry](https://standards-oui.ieee.org/) | MAC address manufacturers in the LAN view (downloaded by `make data`) | IEEE public listing |
| [world-atlas](https://github.com/topojson/world-atlas) / [Natural Earth](https://www.naturalearthdata.com/) | Map outlines | ISC / public domain |
| [Chart.js](https://www.chartjs.org/) | Charts | MIT |
| [D3](https://d3js.org/), [topojson-client](https://github.com/topojson/topojson-client) | Graph, map | ISC |
| [Wireshark / tshark](https://www.wireshark.org/) | Packet capture and dissection (installed separately) | GPL-2.0 |

## Contributing

Please submit bug reports and feature requests via GitHub Issues.
