use retina_core::config::default_config;
use retina_core::subscription::{TlsConnection, TlsConnectionSubscription};
use retina_core::Runtime;
use retina_filtergen::filter;

#[filter("tls.sni ~ '^.*\\.com$'")]
fn main() {
    let cfg = default_config();
    let callback = |tls: TlsConnection| {
        println!("{:?}", tls);
    };
    let mut runtime: Runtime<TlsConnectionSubscription> = Runtime::new(cfg, filter, vec![Box::new(callback)]).unwrap();
    runtime.run();
}