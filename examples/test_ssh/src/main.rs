use retina_core::{config::load_config, Runtime};
use retina_datatypes::{ConnRecord, SshHandshake};
use retina_filtergen::{filter, retina_main};

use std::fs::File;
use std::io::{BufWriter, Write};
use clap::Parser;
use std::path::PathBuf;
use std::sync::Mutex;


static file: Mutex<BufWriter<File>> = Mutex::new(BufWriter::new(File::create("ssh.jsonl")?));

#[derive(Parser, Debug)]
struct Args {
    #[clap(short, long, parse(from_os_str), value_name = "FILE")]
    config: PathBuf,
    #[clap(
        short,
        long,
        parse(from_os_str),
        value_name = "FILE",
        default_value = "ssh.jsonl"
    )]
    outfile: PathBuf,
}

// #[filter("ssh")]
// fn ssh_cb(ssh: &SshHandshake, conn_record: &ConnRecord) {
//     println!("Version Exchange: Client to Server");
//     println!("protoversion: {}, softwareversion: {}, comments: {}", 
//         ssh.protocol_version_ctos(),
//         ssh.software_version_ctos(),
//         ssh.comments_ctos(),
//     );

//     println!("Version Exchange: Server to Client");
//     println!("protoversion: {}, softwareversion: {}, comments: {}", 
//         ssh.protocol_version_stoc(),
//         ssh.software_version_stoc(),
//         ssh.comments_stoc(),
//     );

//     println!("\nKey Exchange");
//     println!("cookie: {:?}", ssh.key_exchange_cookie_stoc());
//     println!("kex_algs: {}", ssh.kex_algs_stoc().join(","));
//     println!("server_host_key_algs: {}", ssh.server_host_key_algs_stoc().join(","));
//     println!("encryption_algs_ctos: {}", ssh.encryption_algs_ctos().join(","));
//     println!("encryption_algs_stoc: {}", ssh.encryption_algs_stoc().join(","));
//     println!("mac_algs_ctos: {}", ssh.mac_algs_ctos().join(","));
//     println!("mac_algs_stoc: {}", ssh.mac_algs_stoc().join(","));
//     println!("compression_algs_ctos: {}", ssh.compression_algs_ctos().join(","));
//     println!("compression_algs_stoc: {}", ssh.compression_algs_stoc().join(","));
//     println!("languages_ctos: {}", ssh.languages_ctos().join(","));
//     println!("languages_stoc: {}", ssh.languages_stoc().join(","));

//     println!("\nconn. metrics: {:?}", conn_record);
// }

#[filter("ssh")]
fn log_ssh(ssh: &SshHandshake) {
    if let Ok(serialized) = serde_json::to_string(&ssh) {
        file.lock().unwrap().write_all(serialized.as_bytes()).unwrap();
        file.lock().unwrap().write_all(b"\n").unwrap();
    }
}

#[retina_main(1)]
fn main() {
    let args = Args::parse();
    let config = load_config(&args.config);

    let mut runtime: Runtime<SubscribedWrapper> = Runtime::new(config, filter).unwrap();
    runtime.run();
}
