use super::parse::{ConfigRaw, SubscriptionRaw};
use quote::ToTokens;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Mutex,
};
use retina_core::filter::datatypes::Streaming;

lazy_static! {
    pub(crate) static ref NUM_SUBSCRIPTIONS: AtomicUsize = AtomicUsize::new(0);
    pub(crate) static ref CACHED_SUBSCRIPTIONS: Mutex<ConfigRaw> = Mutex::new(ConfigRaw {
        subscriptions: vec![]
    });
    pub(crate) static ref STREAMING_SUBSCRIPTIONS: Mutex<Option<Streaming>> =
        Mutex::new(None);
}

pub(crate) fn parse_input(input: &syn::ItemFn) -> (Vec<String>, String) {
    let datatypes = input
        .sig
        .inputs
        .iter()
        .filter_map(|arg| {
            if let syn::FnArg::Typed(syn::PatType { pat: _, ty, .. }) = arg {
                let mut param_type: String = (*ty).to_token_stream().to_string();
                if !param_type.contains("&") {
                    panic!(
                        "Parameters to callbacks must be passed by reference ({})",
                        param_type
                    );
                }
                param_type = param_type.replace("&", "").trim().to_string();
                return Some(param_type);
            }
            None
        })
        .collect();

    let callback = input.sig.ident.to_token_stream().to_string();

    (datatypes, callback)
}

pub(crate) fn add_subscription(callback: String, datatypes: Vec<String>, filter: String) {
    let streaming = {
        let mut lock = STREAMING_SUBSCRIPTIONS.lock().unwrap();
        lock.take() // Move, replacing with None
    };
    if streaming.is_some() {
        println!("Streaming callback: {}={:?}", callback, streaming.unwrap());
    }
    CACHED_SUBSCRIPTIONS
        .lock()
        .unwrap()
        .subscriptions
        .push(SubscriptionRaw {
            filter,
            datatypes,
            callback,
            streaming,
        });
}

pub(crate) fn add_streaming(callback: String, key: &str, value: f32) {
    let mut lock = CACHED_SUBSCRIPTIONS.lock().unwrap();
    if let Some(entry) = lock.subscriptions.last_mut() {
        if entry.callback == callback {
            entry.streaming = Some(Streaming::from((key, value)));
            println!("Streaming callback: {}={:?}", callback, entry.streaming);
            return;
        }
    }

    *STREAMING_SUBSCRIPTIONS.lock().unwrap() = Some(Streaming::from((key, value)));
}

pub(crate) fn is_done() -> bool {
    let present = CACHED_SUBSCRIPTIONS.lock().unwrap().subscriptions.len();
    let expected = NUM_SUBSCRIPTIONS.load(Ordering::SeqCst);
    if present > expected && expected > 0 {
        panic!("Too many subscriptions present; expected: {}", expected);
    }
    present == expected
}

pub(crate) fn set_count(count: usize) {
    NUM_SUBSCRIPTIONS.store(count, Ordering::SeqCst);
}
