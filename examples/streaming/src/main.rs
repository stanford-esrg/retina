use clap::Parser;
/// An example to illustrate the streaming callback interface.
use retina_core::{config::load_config, FiveTuple, Runtime};
use retina_datatypes::*;
use retina_filtergen::{filter, retina_main, streaming};
use std::path::PathBuf;

// Argument parsing
#[derive(Parser, Debug)]
struct Args {
    #[clap(short, long, parse(from_os_str), value_name = "FILE")]
    config: PathBuf,
}

/// This callback will be invoked on every packet for connections
/// that are identified as TLS on TCP port 52152.
/// The callback will begin to be invoked for the first packet
/// following filter match (identification of TLS connection).
/// That is, we expect the initial value of PktCount to be >3
/// (after the TCP handshake and first data packet).
#[filter("tls and tcp.port = 52152")]
#[streaming("packets=1")]
fn tls_cb_pkts(pkts: &PktCount, ft: &FiveTuple) -> bool {
    println!("{} Packet count: {}", ft, pkts.raw());
    true
}

/// This callback will be invoked every 5,000 bytes for connections
/// that are identified as TLS and are not on TCP port 52152.
/// Since the callback is invoked at most every packet, it may not
/// be invoked at intervals of exactly 5,000 bytes.
/// The "timer" for callback invocation will begin once the filter
/// has matched; that is, the initial value of `bytes` will be >5,000
/// as it will include the preamble *plus* ≥5,000 bytes of data.
#[filter("tls and tcp.port != 52152")]
#[streaming("bytes=5000")]
fn tls_cb_bytes(bytes: &ByteCount, ft: &FiveTuple) -> bool {
    println!("{} Byte count: {}", ft, bytes.raw());
    true
}

#[retina_main(2)]
fn main() {
    let args = Args::parse();
    let config = load_config(&args.config);
    let mut runtime: Runtime<SubscribedWrapper> = Runtime::new(config, filter).unwrap();
    runtime.run();
}
