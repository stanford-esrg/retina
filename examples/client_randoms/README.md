# Repeated client randoms

Logs repeated TLS client randoms and their frequencies.

### Build and run
```
cargo build --release --bin client_randoms
sudo env LD_LIBRARY_PATH=$LD_LIBRARY_PATH RUST_LOG=error ./target/release/client_randoms -c <path/to/config.toml>
```