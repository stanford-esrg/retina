# HTTP Logger

Demonstrates logging HTTP request/response transactions to a file.

### Build and run
```
cargo build --release --bin log_http
sudo env LD_LIBRARY_PATH=$LD_LIBRARY_PATH RUST_LOG=error ./target/release/log_http -c <path/to/config.toml>
```