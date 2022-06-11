# Spin cycles

Busy loops inside the callback for a given number of cycles.
This varies the per-callback processing time and approximates the impact of increasing callback complexity.

### Build and run
```
cargo build --release --bin spin
sudo env LD_LIBRARY_PATH=$LD_LIBRARY_PATH RUST_LOG=error ./target/release/spin -c <path/to/config.toml> --spin <num_cycles>
```