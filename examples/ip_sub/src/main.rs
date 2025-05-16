use retina_core::{config::default_config, Runtime};
use retina_datatypes::{ConnRecord, FilterStr};
use retina_filtergen::subscription;

fn ip_cb(conn_record: &ConnRecord, filter_str: &FilterStr) {
    println!("Matched filter {}: {:?}", filter_str, conn_record);
}

#[subscription("./spec.toml")]
fn main() {
    let config = default_config();
    let mut runtime: Runtime<SubscribedWrapper> = Runtime::new(config, filter).unwrap();
    runtime.run();
}