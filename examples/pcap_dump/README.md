# Packet Capture

Demonstrates filtered packet capturing.

### Build and run
```
cargo build --release --bin pcap_dump
sudo env LD_LIBRARY_PATH=$LD_LIBRARY_PATH RUST_LOG=error ./target/release/pcap_dump -c <path/to/config.toml> -o <path/to/output.pcap>
```
