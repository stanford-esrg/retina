use retina_core::{config::load_config, Runtime};
use retina_datatypes::ConnRecord;
use retina_filtergen::subscription;

use clap::Parser;
use lazy_static::lazy_static;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::PathBuf;
use std::sync::Mutex;

lazy_static! {
    static ref file: Mutex<BufWriter<File>> =
        Mutex::new(BufWriter::new(File::create("ip_sub.jsonl").unwrap()));
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
        default_value = "ip_sub.jsonl"
    )]
    outfile: PathBuf,
}

fn ip_cb(conn_record: &ConnRecord) {
    if let Ok(serialized) = serde_json::to_string(&conn_record) {
        let mut wtr = file.lock().unwrap();
        wtr.write_all(serialized.as_bytes()).unwrap();
        wtr.write_all(b"\n").unwrap();
    }
}

#[subscription("./spec.toml")]
fn main() {
    let args = Args::parse();
    let config = load_config(&args.config);

    let mut runtime: Runtime<SubscribedWrapper> = Runtime::new(config, filter).unwrap();
    runtime.run();

    let mut wtr = file.lock().unwrap();
    wtr.flush().unwrap();
}