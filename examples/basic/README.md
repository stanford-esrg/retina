# Basic example usage

A toy Retina application that prints parsed TLS handshakes with domains ending in `.com` to stdout.

### Build and run
```
cargo build --release --bin basic
sudo env LD_LIBRARY_PATH=$LD_LIBRARY_PATH RUST_LOG=error ./target/release/basic
```