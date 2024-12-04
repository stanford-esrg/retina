use retina_core::{config::load_config, Runtime};
use retina_datatypes::{ConnRecord, SshHandshake};
use retina_filtergen::{filter, retina_main};

use std::fs::File;
use std::io::{BufWriter, Write};
use clap::Parser;
use lazy_static::lazy_static;
use std::path::PathBuf;
use std::sync::Mutex;

lazy_static! {
    static ref file: Mutex<BufWriter<File>> = Mutex::new(
        BufWriter::new(File::create("ssh.jsonl").unwrap())
    );
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

#[filter("ssh")]
fn log_ssh(ssh: &SshHandshake, conn_record: &ConnRecord) {
    if let Ok(serialized) = serde_json::to_string(&ssh) {
        let conn_metrics = serde_json::to_string(&conn_record);
        let mut wtr = file.lock().unwrap();
        wtr.write_all(serialized.as_bytes()).unwrap();
        wtr.write_all(b"\n").unwrap();
        wtr.write_all(conn_metrics.unwrap().as_bytes()).unwrap();
        wtr.flush().unwrap();
    }
}

#[retina_main(1)]
fn main() {
    let args = Args::parse();
    let config = load_config(&args.config);

    let mut runtime: Runtime<SubscribedWrapper> = Runtime::new(config, filter).unwrap();
    runtime.run();
}
