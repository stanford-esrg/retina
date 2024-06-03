# HTTP Logger

Demonstrates logging Quic transactions to a file.

### Build and run
```
cargo build --release --bin log_quic
sudo env LD_LIBRARY_PATH=$LD_LIBRARY_PATH RUST_LOG=error ./target/release/log_quic -c <path/to/config.toml>
```