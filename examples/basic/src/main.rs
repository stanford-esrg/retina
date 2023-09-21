use retina_core::config::default_config;
use retina_core::subscription::{SubscribableEnum, SubscribableWrapper};
use retina_core::Runtime;
use retina_filtergen::filter;

#[filter]
fn main() {
    let cfg = default_config();
    let callback = |tls: SubscribableEnum| {
        println!("CB 1: {:?}", tls);
    };
    let callback2 = | http: SubscribableEnum| {
        println!("CB 2: {:?}", http);
    };
    let mut runtime: Runtime<SubscribableWrapper> = Runtime::new(cfg, filter, 
                                                    vec![Box::new(callback), Box::new(callback2)]).unwrap();
    runtime.run();
}


/*
use retina_subscriptiongen::subscription_type;

#[subscription_type]
struct Dummy {}

fn main() {}
 */
