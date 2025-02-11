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
        File::create("byte_regex.jsonl").unwrap()
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
        default_value = "byte_regex.jsonl"
    )]
    outfile: PathBuf,
}

// match any server name starting with www. and ending in .com??

// match any server name ending in .com
#[filter("tls.sni ~ |2E 63 6F 6D|")]
fn tls_cb(tls: &TlsHandshake) {
    print("Tls SNI: {}", tls.sni())
    if let Ok(serialized) = serde_json::to_string(&tls) {
        let mut wtr = file.lock().unwrap();
        wtr.write_all(serialized.as_bytes()).unwrap();
        wtr.write_all(b"\n").unwrap();
    }
}

// // na4.salesforce.com
// #[filter("tls.sni = |6e 61 34 2e 73 61 6c 65 73 66 6f 72 63 65 2e 63 6f 6d|")]
// fn tls_cb2(tls: &TlsHandshake) {
//     if let Ok(serialized) = serde_json::to_string(&tls) {
//         let mut wtr = file.lock().unwrap();
//         wtr.write_all(serialized.as_bytes()).unwrap();
//         wtr.write_all(b"\n").unwrap();
//     }
// }

#[retina_main(1)]
fn main() {
    let config = default_config();
    let mut runtime: Runtime<SubscribedWrapper> = Runtime::new(config, filter).unwrap();
    runtime.run();

    let mut wtr = file.lock().unwrap();
    wtr.flush().unwrap();
}
