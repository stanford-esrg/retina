use retina_core::config::load_config;
use retina_core::subscription::{Subscribed, SubscribableWrapper};
use retina_core::Runtime;
use retina_filtergen::retina_main;

use std::path::PathBuf;

use clap::Parser;

#[derive(Parser, Debug)]
struct Args {
    #[clap(
        short, 
        long, 
        parse(from_os_str), 
        value_name = "FILE",
        default_value = "configs/online.toml"
    )]
    config: PathBuf,
}

#[allow(unused)]
fn no_op(_data: Subscribed) { }

#[allow(unused)]
fn callback1(data: Subscribed) {
    if let Subscribed::TlsSubscription(tls) = data {
        println!("CB 1: {:?}", tls);
    } else if let Subscribed::HttpSubscription(http) = data {
        println!("CB 1: {:?}", http);
    }
}

#[allow(unused)]
fn callback2(data: Subscribed) {
    println!("CB 2: {:?}", data);
}

#[retina_main]
fn main() {
    env_logger::init();
    let args = Args::parse();
    let config = load_config(&args.config);
    let mut runtime: Runtime<SubscribableWrapper> = Runtime::new(config, filter, 
                                                    callbacks()).unwrap();  
    runtime.run();
}