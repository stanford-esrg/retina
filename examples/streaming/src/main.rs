use retina_core::{config::load_config, FiveTuple, Runtime};
use retina_datatypes::*;
use retina_filtergen::{filter, retina_main, streaming};
use std::path::PathBuf;
use clap::Parser;

// Argument parsing
#[derive(Parser, Debug)]
struct Args {
    #[clap(short, long, parse(from_os_str), value_name = "FILE")]
    config: PathBuf,
}

#[filter("tls and tcp.port = 52152")]
#[streaming("packets=1")]
fn tls_cb_pkts(pkts: &PktCount, ft: &FiveTuple) -> bool {
    println!("{} Packet count: {}", ft, pkts.raw());
    true
}

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
