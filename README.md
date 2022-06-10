# Retina

![build-status](https://github.com/stanford-esrg/retina/actions/workflows/ci.yml/badge.svg)

Retina is a framework for network traffic analysis and measurement with a focus on expressiveness, performance, deployability, and security. Retina allows users to easily *subscribe* to network data in real-time and run arbitrary analysis code in a standard software environment.

- **Expressiveness** Retina supports arbitrarily complex processing of individual packets, reassembled connections, or parsed application-layer sessions using a simple filter and callback interface.

- **Performance** Retina is capable of real-time traffic analysis in high volume (100G+) environments, such as regional ISPs or academic institutions

- **Deployability** Retina is readily deployable on a single multi-core server with a commodity 100G NIC.

- **Security** Retina leverages compile-time memory safety guarantees offered by Rust to safely and efficiently process network traffic.

## Getting Started
Install [Rust](https://www.rust-lang.org/tools/install) and [DPDK](http://core.dpdk.org/download/). Detailed instructions can be found in [INSTALL](INSTALL.md).

Add `$DPDK_PATH/lib/x86_64-linux-gnu` to your `LD_LIBRARY_PATH`, where `DPDK_PATH` points to the DPDK installation directory.

Clone the main git repository:

`git clone git@github.com:stanford-esrg/retina.git`

Write your first Retina application (see [examples](https://github.com/stanford-esrg/retina/tree/main/examples)):
```
use retina_core::config::default_config;
use retina_core::subscription::TlsHandshake;
use retina_core::Runtime;
use retina_filtergen::filter;

#[filter("tls.sni ~ '^.*\\.com$'")]
fn main() {
    let cfg = default_config();
    let callback = |tls: TlsHandshake| {
        println!("{:?}", tls);
    };
    let mut runtime = Runtime::new(cfg, filter, callback).unwrap();
    runtime.run();
}
```

Build:

`cargo build --release`

Run:

`sudo env LD_LIBRARY_PATH=$LD_LIBRARY_PATH RUST_LOG=info ./target/release/my_app -c config.toml`

## Development

Build one application:

`cargo build --bin my_app`

Run in debug mode:

`sudo env LD_LIBRARY_PATH=$LD_LIBRARY_PATH RUST_LOG=debug ./target/debug/my_app -c config.toml`

Filter expansion:

`cargo expand --manifest-path=examples/my_app/Cargo.toml`

