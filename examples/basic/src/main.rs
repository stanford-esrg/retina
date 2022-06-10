use retina_core::config::default_config;
use retina_core::subscription::*;
use retina_core::Runtime;
use retina_filtergen::filter;

#[filter("tls.sni ~ '^.*\\.com$'")]
fn main() {
    let cfg = default_config();
    let callback = |tls: TlsHandshake| {
        println!("{:?}", tls);
    };
    let mut runtime = Runtime::new(cfg, filter, callback).unwrap();
    runtime.run();
}
