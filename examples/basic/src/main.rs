use retina_core::config::load_config;
use retina_core::Runtime;

mod subscription;
use clap::Parser;
use std::path::PathBuf;
use subscription::*;

#[derive(Parser, Debug)]
struct Args {
    #[clap(short, long, parse(from_os_str), value_name = "FILE")]
    config: PathBuf,
}

fn main() {
    let args = Args::parse();
    let config = load_config(&args.config);
    let mut runtime: Runtime<SubscribedWrapper> = Runtime::new(config, filter).unwrap();
    runtime.run();
    print();
}
