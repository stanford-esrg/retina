use retina_core::config::default_config;
use retina_core::subscription::{SubscribableEnum, SubscribableWrapper};
use retina_core::Runtime;
use retina_filtergen::filter;

#[allow(unused)]
fn no_op(_data: SubscribableEnum) { }

#[allow(unused)]
fn callback1(data: SubscribableEnum) {
    if let SubscribableEnum::Tls(tls) = data {
        println!("CB 1: {:?}", tls);
    } else if let SubscribableEnum::Http(http) = data {
        println!("CB 1: {:?}", http);
    }
}

#[allow(unused)]
fn callback2(data: SubscribableEnum) {
    println!("CB 2: {:?}", data);
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
