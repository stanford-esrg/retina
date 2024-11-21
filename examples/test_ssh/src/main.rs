use retina_core::config::{load_config, Runtime};
use retina_core::subscription::Connection;
use retina_datatypes::{ConnRecord, SshTransaction};
use retina_filtergen::{filter, retina_main};

use std::path::PathBuf;

use anyhow::Result;
use clap::Parser;

#[derive(Parser, Debug)]
struct Args {
    #[clap(short, long, parse(from_os_str), value_name = "FILE")]
    config: PathBuf,
}

#[filter("ssh")]
fn ssh_cb(ssh: &SshTransaction, five_tuple: &FiveTuple) {

}

fn main() {
    let args = Args::parse();
    let config = load_config(&args.config);

    let mut runtime: Runtime<SubscribedWrapper> = Runtime::new(config, filter).unwrap();
    runtime.run();

    Ok(())
}
