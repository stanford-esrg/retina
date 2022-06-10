use retina_core::config::default_config;
use retina_core::subscription::TlsHandshake;
use retina_core::Runtime;
use retina_filtergen::filter;

#[filter("tcp")]
fn main() {
    let cfg = default_config();
    let callback = |tls: TlsHandshake| {
        println!("{:?}", tls);
    };
    let mut runtime = Runtime::new(cfg, filter, callback).unwrap();
    runtime.run();
}
