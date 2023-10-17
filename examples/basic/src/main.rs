use retina_core::config::default_config;
use retina_core::subscription::{Subscribed, SubscribableWrapper};
use retina_core::Runtime;
use retina_filtergen::retina_main;

#[allow(unused)]
fn no_op(_data: Subscribed) { }

#[allow(unused)]
fn callback1(data: Subscribed) {
    if let Subscribed::TlsSubscription(tls) = data {
        println!("CB 1: {:?}", tls);
    } else if let Subscribed::HttpSubscription(http) = data {
        println!("CB 1: {:?}", http);
    }
}

#[allow(unused)]
fn callback2(data: Subscribed) {
    println!("CB 2: {:?}", data);
}

#[retina_main]
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
