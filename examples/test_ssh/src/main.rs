use retina_core::{config::load_config, Runtime};
// use retina_core::subscription::Connection;
use retina_datatypes::{ConnRecord, SshHandshake};
use retina_filtergen::{filter, retina_main};

use clap::Parser;
use std::path::PathBuf;

#[derive(Parser, Debug)]
struct Args {
    #[clap(short, long, parse(from_os_str), value_name = "FILE")]
    config: PathBuf,
}

// #[filter("ssh")]
// fn frame_cb(mbuf: &ZcFrame) {
//     let contents = mbuf.data();
//     println!("mbuf data: {:x?}", contents);
// }

// #[filter("ssh")]
// fn five_tuple_cb(five_tuple: &FiveTuple, pkts: &PktCount) {
//     let dst_port = five_tuple.resp.port();
//     let src_port = five_tuple.orig.port();
//     println!("dst_port: {:?}", dst_port);
//     println!("src_port: {:?}", src_port);
// }

#[filter("ssh")]
fn ssh_cb(ssh: &SshHandshake, conn_record: &ConnRecord) {
    println!(
        "SSH: protoversion: {}, softwareversion: {}, comments: {}, conn. metrics: {:?}",
        ssh.protocol_version(),
        ssh.software_version(),
        ssh.comments(),
        conn_record
    );
}

#[retina_main(1)]
fn main() {
    let args = Args::parse();
    let config = load_config(&args.config);

    let mut runtime: Runtime<SubscribedWrapper> = Runtime::new(config, filter).unwrap();
    runtime.run();
}
