use retina_core::{config::default_config, Runtime};
use retina_datatypes::TlsHandshake;
use retina_filtergen::{filter, retina_main};

// www.google.com
#[filter("tls.sni = |77 77 77 2E 67 6F 6F 67 6C 65 2E 63 6F 6D|")]
fn tls_cb(tls: &TlsHandshake) {
    println!("cb1: Tls SNI: {}", tls.sni());
}

// calendar.google.com
#[filter("tls.sni = |63 61 6c 65 6e 64 61 72 2e 67 6f 6f 67 6C 65 2e 63 6f 6d|")]
fn tls_cb2(tls: &TlsHandshake) {
    println!("cb2: Tls SNI: {}", tls.sni());
}

// na4.salesforce.com
#[filter("tls.sni = |6e 61 34 2e 73 61 6c 65 73 66 6f 72 63 65 2e 63 6f 6d|")]
fn tls_cb3(tls: &TlsHandshake) {
    println!("cb3: Tls SNI: {}", tls.sni());
}

#[retina_main(3)]
fn main() {
    let config = default_config();
    let mut runtime: Runtime<SubscribedWrapper> = Runtime::new(config, filter).unwrap();
    runtime.run();
}
