use retina_core::{config::default_config, Runtime};
use retina_datatypes::{FilterStr, TlsHandshake};
use retina_filtergen::subscription;

fn tls_cb(tls: &TlsHandshake, filter_str: &FilterStr) {
    println!("Matched filter {}: {:?}", filter_str, tls);
}

#[subscription("./examples/basic_file/spec.toml")]
fn main() {
    let config = default_config();
    let mut runtime: Runtime<SubscribedWrapper> = Runtime::new(config, filter).unwrap();
    runtime.run();
}
