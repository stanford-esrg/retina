use retina_core::{config::load_config, Runtime};
use retina_datatypes::SshHandshake;
use retina_filtergen::{filter, retina_main};

use clap::Parser;
use lazy_static::lazy_static;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::PathBuf;
use std::sync::Mutex;

lazy_static! {
    static ref file: Mutex<BufWriter<File>> =
        Mutex::new(BufWriter::new(File::create("ssh.jsonl").unwrap()));
}

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

#[filter("ssh.protocol_version_ctos = |32 2E 30|")]
fn ssh_byte_match_cb(ssh: &SshHandshake) {
    if let Ok(serialized) = serde_json::to_string(&ssh) {
        let mut wtr = file.lock().unwrap();
        wtr.write_all(serialized.as_bytes()).unwrap();
        wtr.write_all(b"\n").unwrap();
    }
}

#[filter("ssh.key_exchange_cookie_stoc contains |15 1A|")]
fn ssh_contains_bytes_cb(ssh: &SshHandshake) {
    if let Ok(serialized) = serde_json::to_string(&ssh) {
        let mut wtr = file.lock().unwrap();
        wtr.write_all(serialized.as_bytes()).unwrap();
        wtr.write_all(b"\n").unwrap();
    }
}

#[filter("ssh.software_version_ctos not contains 'OpenSSH'")]
fn ssh_contains_str_cb(ssh: &SshHandshake) {
    if let Ok(serialized) = serde_json::to_string(&ssh) {
        let mut wtr = file.lock().unwrap();
        wtr.write_all(serialized.as_bytes()).unwrap();
        wtr.write_all(b"\n").unwrap();
    }
}

#[filter("ssh.key_exchange_cookie_stoc ~b '(?-u)^\x15\x1A.+\x78$'")]
fn ssh_byte_regex_byte_cb(ssh: &SshHandshake) {
    if let Ok(serialized) = serde_json::to_string(&ssh) {
        let mut wtr = file.lock().unwrap();
        wtr.write_all(serialized.as_bytes()).unwrap();
        wtr.write_all(b"\n").unwrap();
    }
}

#[retina_main(4)]
fn main() {
    let args = Args::parse();
    let config = load_config(&args.config);

    let mut runtime: Runtime<SubscribedWrapper> = Runtime::new(config, filter).unwrap();
    runtime.run();

    let mut wtr = file.lock().unwrap();
    wtr.flush().unwrap();
}
