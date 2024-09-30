use std::sync::{atomic::{AtomicUsize, Ordering}, Mutex};
use super::parse::{ConfigRaw, SubscriptionRaw,};
use quote::ToTokens;

lazy_static! {
    pub(crate) static ref NUM_SUBSCRIPTIONS: AtomicUsize = AtomicUsize::new(0);
    pub(crate) static ref CACHED_SUBSCRIPTIONS: Mutex<ConfigRaw> =
                    Mutex::new(ConfigRaw { subscriptions: vec![] });
}

pub(crate) fn parse_input(input: &syn::ItemFn) -> (Vec<String>, String) {
    let datatypes = input.sig.inputs.iter().filter_map(|arg| {
        if let syn::FnArg::Typed(syn::PatType { pat: _, ty, .. }) = arg {
            let mut param_type: String = (*ty).to_token_stream().to_string();
            if !param_type.contains("&") {
                panic!("Parameters to callbacks must be passed by reference ({})", param_type);
            }
            param_type = param_type.replace("&", "").trim().to_string();
            return Some(param_type);
        }
        None
    }).collect();

    let callback = input.sig.ident.to_token_stream().to_string();

    (datatypes, callback)
}


pub(crate) fn add_subscription(callback: String, datatypes: Vec<String>, filter: String) {
    CACHED_SUBSCRIPTIONS.lock()
                        .unwrap()
                        .subscriptions
                        .push( SubscriptionRaw {
                            filter,
                            datatypes,
                            callback
                        } );
}

pub(crate) fn is_done() -> bool {
    CACHED_SUBSCRIPTIONS.lock().unwrap().subscriptions.len() ==
        NUM_SUBSCRIPTIONS.load(Ordering::SeqCst)
}

pub(crate) fn set_count(count: usize) {
    NUM_SUBSCRIPTIONS.store(count, Ordering::SeqCst);
}

