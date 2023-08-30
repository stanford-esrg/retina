use retina_core::config::load_config;
use retina_core::subscription::{ConnectionFrameSubscription, ConnectionFrame};
use retina_core::Runtime;
use retina_filtergen::filter;

use std::path::PathBuf;

use anyhow::Result;
use clap::Parser;
use pnet::packet::ethernet::MutableEthernetPacket as Ethernet;
use pnet::packet::ipv4::MutableIpv4Packet as Ipv4;
use pnet::packet::MutablePacket;

#[derive(Parser, Debug)]
struct Args {
    #[clap(short, long, parse(from_os_str), value_name = "FILE")]
    config: PathBuf,
}

#[filter("http")]
fn main() -> Result<()> {
    env_logger::init();
    let args = Args::parse();
    let config = load_config(args.config);

    let key: [u8; 16] = "a sample enc key".as_bytes().try_into()?;
    let callback = |frame: ConnectionFrame| {
        if let Some(mut eth) = Ethernet::owned(frame.data) {
            let payload = Ethernet::payload_mut(&mut eth);
            if let Some(mut ipv4) = Ipv4::new(payload) {
                let src_anon = ipcrypt::encrypt(Ipv4::get_source(&ipv4), &key);
                let dst_anon = ipcrypt::encrypt(Ipv4::get_destination(&ipv4), &key);
                Ipv4::set_source(&mut ipv4, src_anon);
                Ipv4::set_destination(&mut ipv4, dst_anon);
            }
        }
    };
    let mut runtime: Runtime<ConnectionFrameSubscription> = Runtime::new(config, filter, vec![Box::new(callback)]).unwrap();
    runtime.run();
    Ok(())
}
