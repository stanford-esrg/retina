use retina_core::{config::default_config, Runtime};
use retina_datatypes::TlsHandshake;
use retina_filtergen::{filter, retina_main};

use clap::Parser;
use lazy_static::lazy_static;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::PathBuf;
use std::sync::Mutex;

lazy_static! {
    static ref file: Mutex<BufWriter<File>> = Mutex::new(BufWriter::new(
        File::create("contains_test.jsonl").unwrap()
    ));
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
        default_value = "contains_test.jsonl"
    )]
    outfile: PathBuf,
}

// check if contains b"google"
#[filter("tls.sni contains |67 6F 6F 67 6C 65|")]
fn tls_cb(tls: &TlsHandshake) {
    println!("cb1: Tls.SNI: {}", tls.sni());
    if let Ok(serialized) = serde_json::to_string(&tls) {
        let mut wtr = file.lock().unwrap();
        wtr.write_all(serialized.as_bytes()).unwrap();
        wtr.write_all(b"\n").unwrap();
    }
}

// check if contains "salesforce"
#[filter("tls.sni contains 'salesforce'")]
fn tls_cb2(tls: &TlsHandshake) {
    println!("cb2: Tls.SNI: {}", tls.sni());
   if let Ok(serialized) = serde_json::to_string(&tls) {
       let mut wtr = file.lock().unwrap();
       wtr.write_all(serialized.as_bytes()).unwrap();
       wtr.write_all(b"\n").unwrap();
   }
}

#[retina_main(2)]
fn main() {
    let config = default_config();
    let mut runtime: Runtime<SubscribedWrapper> = Runtime::new(config, filter).unwrap();
    runtime.run();

    let mut wtr = file.lock().unwrap();
    wtr.flush().unwrap();
}
