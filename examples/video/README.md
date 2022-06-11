# Video streaming feature extraction

Proof of concept example that aggregates network flows within Netflix video sessions to extract several features used in [Inferring Streaming Video Quality from Encrypted Traffic: Practical Models and Deployment Experience](https://dl.acm.org/doi/pdf/10.1145/3366704) to infer video quality metrics. These include the number of parallel flows, total bytes up/down, average number of out-of-order packets up/down, and total download throughput.

### Build and run
```
cargo build --release --bin video
sudo env LD_LIBRARY_PATH=$LD_LIBRARY_PATH RUST_LOG=error ./target/release/video -c <path/to/config.toml>
```