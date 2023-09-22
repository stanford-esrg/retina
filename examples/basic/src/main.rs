use retina_core::config::default_config;
use retina_core::subscription::{SubscribableEnum, SubscribableWrapper};
use retina_core::Runtime;
use retina_filtergen::filter;

fn callback1(tls: SubscribableEnum) {
    println!("CB 1: {:?}", tls);
}

fn callback2(http: SubscribableEnum) {
    println!("CB 2: {:?}", http);
}

#[filter]
fn main() {
    let cfg = default_config();
    let mut runtime: Runtime<SubscribableWrapper> = Runtime::new(cfg, filter, 
                                                    callbacks()).unwrap();
    runtime.run();
}


/*
use retina_subscriptiongen::subscription_type;

#[subscription_type]
struct Dummy {}

fn main() {}
 */
