# IP address anonymization

Anonymizes the source and destination IPv4 addresses in HTTP flows.

### Build and run
```
cargo build --release --bin ip_anon
sudo env LD_LIBRARY_PATH=$LD_LIBRARY_PATH RUST_LOG=error ./target/release/ip_anon -c <path/to/config.toml>
```