use retina_core::{config::default_config, Runtime};
use retina_datatypes::TlsHandshake;
use retina_filtergen::{filter, retina_main};

#[filter("tls.sni == |00 01 02 03|")]
fn tls_cb(tls: &TlsHandshake) {
    println!("Tls SNI: {}", tls.sni());
}

#[retina_main(1)]
fn main() {
    let config = default_config();
    let mut runtime: Runtime<SubscribedWrapper> = Runtime::new(config, filter).unwrap();
    runtime.run();
}