# DNS log

Demonstrates logging all DNS query/response transactions to a file.

### Build and run
```
cargo build --release --bin log_dns
sudo env LD_LIBRARY_PATH=$LD_LIBRARY_PATH RUST_LOG=error ./target/release/log_dns -c <path/to/config.toml>
```
