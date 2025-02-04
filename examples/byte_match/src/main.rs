use retina_core::{config::default_config, Runtime};
use retina_datatypes::TlsHandshake;
use retina_filtergen::{filter, retina_main};

#[filter("tls.sni = |77 77 77 2E 67 6F 6F 67 6C 65 2E 63 6F 6D|")]
fn tls_cb(tls: &TlsHandshake) {
    println!("Tls SNI: {}", tls.sni());
}

#[retina_main(1)]
fn main() {
    let config = default_config();
    let mut runtime: Runtime<SubscribedWrapper> = Runtime::new(config, filter).unwrap();
    runtime.run();
}
