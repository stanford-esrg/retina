# Connection Logger

Demonstrates logging connection records to a file.

### Build and run
```
cargo build --release --bin log_conn
sudo env LD_LIBRARY_PATH=$LD_LIBRARY_PATH RUST_LOG=error ./target/release/log_conn -c <path/to/config.toml>
```
