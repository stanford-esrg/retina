use retina_core::config::default_config;
use retina_core::Runtime;

mod subscription;
use subscription::*;

fn main() {
    let cfg = default_config();
    let mut runtime: Runtime<SubscribedWrapper> = Runtime::new(cfg, filter).unwrap();
    runtime.run();
}