# Retina

[![build-status](https://github.com/stanford-esrg/retina/actions/workflows/ci.yml/badge.svg)](https://github.com/stanford-esrg/retina/actions)
[![doc-status](https://github.com/stanford-esrg/retina/actions/workflows/rustdoc.yml/badge.svg)](https://stanford-esrg.github.io/retina/retina_core)

Retina is a network analysis framework that enables operators and researchers
to ask complex questions about high-speed (>100gbE) network links. Retina
allows users to easily *subscribe* to subsets of parsed application-layer
sessions, reassembled network flows, or raw packets in real-time and to run
arbitrary analysis code in a standard Rust-based software environment. Retina
optimizes for:

- **Expressiveness:** Retina supports arbitrarily complex processing of
  individual packets, reassembled connections, or parsed application-layer
  sessions using a simple filter and callback interface.

- **Performance:** Retina is capable of real-time traffic analysis in high
  volume (100G+) environments, such as ISPs or academic institutions.

- **Deployability:** Retina is readily deployable on a single multi-core server
  with commodity 100gbE NICs (e.g., Mellanox ConnectX-5 or Intel E810).

- **Security:** Retina leverages compile-time memory safety guarantees offered
  by Rust to safely and efficiently process network traffic.

## Documentation

A detailed description of Retina's architecture and its performance can be
found in our SIGCOMM'22 paper: *[Retina: Analyzing 100 GbE Traffic on Commodity
Hardware](https://thegwan.github.io/files/retina.pdf)*.

Documentation for using and developing against Retina can be found
[here](https://stanford-esrg.github.io/retina/retina_core/). It includes a
comprehensive description of supported filter syntax and subscribable types.


## Getting Started

Install [Rust](https://www.rust-lang.org/tools/install) and
[DPDK](http://core.dpdk.org/download/). Detailed instructions can be found in
[INSTALL](INSTALL.md).

Add `$DPDK_PATH/lib/x86_64-linux-gnu` to your `LD_LIBRARY_PATH`, where `DPDK_PATH` points to the DPDK installation directory.

Fork or clone the main git repository:

`git clone git@github.com:stanford-esrg/retina.git`

Write your first Retina application (see [examples](https://github.com/stanford-esrg/retina/tree/main/examples)):
```rust
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

Build all examples in release mode:

`cargo build --release`

Run `basic` in release mode:

`sudo env LD_LIBRARY_PATH=$LD_LIBRARY_PATH RUST_LOG=error ./target/release/basic`

## Development

Build a single application in debug mode:

`cargo build --bin my_app`

Run in debug mode:

`sudo env LD_LIBRARY_PATH=$LD_LIBRARY_PATH RUST_LOG=debug ./target/debug/my_app`

Filter expansion (requires Rust nightly):

`cargo expand --manifest-path=examples/my_app/Cargo.toml`

## Contributing

Contributions welcome! Please run `cargo fmt` and `cargo clippy` before making a pull request.

## Reproducibility

A [Docker image](https://github.com/tbarbette/retina-docker) is available to run Retina without the hassle of installing DPDK and other dependencies. It is, however, not suitable for performance testing as it uses the DPDK PCAP driver and is limited to a single core. The GitHub repository also includes a tutorial and a video to start learning about Retina.

A [CloudLab image](https://github.com/tbarbette/retina-expe) is available to reproduce a few of the experiments shown in the paper on the CloudLab public testbed. The repository also includes the scripts and information to reproduce these experiments on your own testbed.

## Acknowledgements

Retina was developed with support from the National Science Foundation under
award CNS-2124424, and through gifts from Google, Inc., Cisco Systems, Inc.,
and Comcast Corporation.

