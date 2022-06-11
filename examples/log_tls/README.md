# TLS Logger

Demonstrates logging TLS handshakes to a file.

### Build and run
```
cargo build --release --bin log_tls
sudo env LD_LIBRARY_PATH=$LD_LIBRARY_PATH RUST_LOG=error ./target/release/log_tls -c <path/to/config.toml>
```