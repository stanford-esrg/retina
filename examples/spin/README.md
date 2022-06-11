# Spin cycles

Busy loops inside the callback for a given number of cycles. This varies the per-callback processing
time and approximates the impact of increasing callback complexity.

To view the effects of busy looping, run Retina in online mode with live monitoring
display enabled and observe the packet drop rate.

### Build and run
```
cargo build --release --bin spin
sudo env LD_LIBRARY_PATH=$LD_LIBRARY_PATH RUST_LOG=error ./target/release/spin -c <path/to/config.toml> --spin <num_cycles>
```