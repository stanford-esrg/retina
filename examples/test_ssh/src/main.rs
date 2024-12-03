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
    println!("Version Exchange: Client to Server");
    println!("protoversion: {}, softwareversion: {}, comments: {}", 
        ssh.protocol_version_ctos(),
        ssh.software_version_ctos(),
        ssh.comments_ctos(),
    );

    println!("Version Exchange: Server to Client");
    println!("protoversion: {}, softwareversion: {}, comments: {}\n", 
        ssh.protocol_version_stoc(),
        ssh.software_version_stoc(),
        ssh.comments_stoc(),
    );

    println!("\nKey Exchange: Server to Client");
    println!("cookie: {:?}", ssh.key_exchange_cookie_stoc());
    println!("kex_algs: {}", ssh.key_exchange_algs_stoc().join(","));
    println!("server_host_key_algs: {}", ssh.server_host_key_algs_stoc().join(","));
    println!("encryption_algs_ctos: {}", ssh.encryption_algs_ctos_stoc().join(","));
    println!("encryption_algs_stoc: {}", ssh.encryption_algs_stoc().join(","));
    println!("mac_algs_ctos: {}", ssh.mac_algs_ctos_stoc().join(","));
    println!("mac_algs_stoc: {}", ssh.mac_algs_stoc().join(","));
    println!("compression_algs_ctos: {}", ssh.compression_algs_ctos_stoc().join(","));
    println!("compression_algs_stoc: {}", ssh.compression_algs_stoc().join(","));
    println!("languages_ctos: {}", ssh.languages_ctos_stoc().join(","));
    println!("languages_stoc: {}", ssh.languages_stoc().join(","));

    println!("\nDH Init");
    println!("e: {:?}", ssh.dh_init_e());
    
    println!("\nDH Reply");
    println!("pubkey_and_certs: {:?}", ssh.dh_response_pubkey_and_certs());
    println!("f: {:?}", ssh.dh_response_f());
    println!("signature: {:?}", ssh.dh_response_signature());

    println!("\nconn. metrics: {:?}", conn_record);
}

#[retina_main(1)]
fn main() {
    let args = Args::parse();
    let config = load_config(&args.config);

    let mut runtime: Runtime<SubscribedWrapper> = Runtime::new(config, filter).unwrap();
    runtime.run();
}
