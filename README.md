# WebShark

🦈 A web-based network analysis tool for real-time packet visualization on Linux gateways.

## Features

- 🚀 **Simple Setup**: Single binary written in Rust
- 📊 **Real-time Visualization**: Dynamic updates via WebSocket
- 🔍 **tshark Integration**: Uses Wireshark's tshark command
- 🎨 **Beautiful UI**: Modern web interface
- 📈 **Statistics**: Protocol-wise and source/destination statistics
- ⚡ **High Performance**: Compressed WebSocket communication
- 🔧 **Flexible Filtering**: tshark filter support and localhost toggle

## Requirements

### System Requirements
- Linux OS (Ubuntu, CentOS, Debian, etc.)
- Rust 1.70+
- Wireshark (tshark command)

### Installation

1. **Install Wireshark**:
   ```bash
   # Ubuntu/Debian
   sudo apt update
   sudo apt install wireshark-common
   
   # CentOS/RHEL
   sudo yum install wireshark-cli
   
   # or
   sudo dnf install wireshark-cli
   ```

2. **Set Permissions** (Important):
   ```bash
   # Add to wireshark group
   sudo usermod -a -G wireshark $USER
   
   # Or allow tshark to run without sudo
   sudo setcap cap_net_raw,cap_net_admin=eip /usr/bin/tshark
   ```

3. **Install Rust** (if needed):
   ```bash
   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
   source ~/.cargo/env
   ```

## Build and Run

1. **Build the project**:
   ```bash
   cargo build --release
   ```

2. **Run**:
   ```bash
   # Run with administrator privileges (for network interface access)
   sudo ./target/release/webshark
   ```

3. **Access via browser**:
   ```
   http://localhost:3000
   ```

## Usage

1. Access `http://localhost:3000` in your browser
2. Click "Start" button to begin packet capture
3. Real-time packet information will be displayed
4. Statistics are automatically updated
5. IPv6 and ARP addresses are also detected. If no address information is present, `Unknown` will be displayed.

## Configuration Options

### Interface Specification
By default, all interfaces (`any`) are monitored. To specify a particular interface,
modify line 129 of `src/main.rs`:

```rust
.args(&[
    "-i", "eth0",  // Specific interface
    // ...
])
```

### Port Change
To change the default port 3000, modify line 97:

```rust
let listener = tokio::net::TcpListener::bind("0.0.0.0:8080").await.unwrap();
```

## Troubleshooting

### 1. tshark not found
Check with:
```bash
which tshark
```
Ensure the path is correct.

### 2. Permission errors
Run with:
```bash
sudo ./target/release/webshark
```
or perform the permission setup mentioned above.

### 3. Network interface not found
Check available interfaces with:
```bash
ip link show
```

### 4. WebSocket connection errors
Ensure port 3000 is open in the firewall:
```bash
sudo ufw allow 3000
```

## Development

### Log output
```bash
RUST_LOG=debug cargo run
```

### Hot reload
```bash
cargo watch -x run
```

## Security Notes

- This tool requires administrator privileges to run
- Set appropriate access restrictions in production environments
- Consider privacy when monitoring network traffic

## License

MIT License

## Contributing

Please submit bug reports and feature requests via GitHub Issues.