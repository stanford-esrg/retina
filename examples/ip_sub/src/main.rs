use retina_core::{config::load_config, Runtime};
use retina_datatypes::{ConnRecord, FilterStr};
use retina_filtergen::subscription;

use clap::Parser;
use std::path::PathBuf;

#[derive(Parser, Debug)]
struct Args {
    #[clap(short, long, parse(from_os_str), value_name = "FILE")]
    config: PathBuf,
}

fn ip_cb(conn_record: &ConnRecord, filter_str: &FilterStr) {
    println!("Matched filter {}: {:?}", filter_str, conn_record);
}

#[subscription("./spec.toml")]
fn main() {
    let args = Args::parse();
    let config = load_config(&args.config);
    let mut runtime: Runtime<SubscribedWrapper> = Runtime::new(config, filter).unwrap();
    runtime.run();
}