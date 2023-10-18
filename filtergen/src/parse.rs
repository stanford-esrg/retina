use serde_yaml::{Value, from_reader};
use std::collections::HashSet;
use retina_core::filter::{Filter, ptree::PTree};
use quote::quote;
use proc_macro2::{Ident, Span};
use std::env; 

// --- Config Parsing ---
pub(crate) fn get_configs() -> Value {
    let filepath_in = env::var("IN_FILE")
                              .expect("Provide IN_FILE yaml file variable");
    let f_in = std::fs::File::open(&filepath_in)
                .expect(&format!("Failed to read config filepath ({})", &filepath_in));
    let data_in: Value = from_reader(f_in)
                                    .expect("Failed to read subscription config");

    data_in
}

// --- Filter Parsing ---
pub(crate) fn get_filters_from_config(data_in: Value) -> (PTree, String, String) {

    // Read filters from yml file into vector.
    let filters = data_in.get("filters")
                                 .expect("Must specify at least one \"filters\"");
    let iter = filters.as_mapping().unwrap(); 
    let mut filters = vec![];
    let mut filter_idxs = vec![];
    for (k, v) in iter {
        let idxs = v.as_sequence().unwrap(); 
        for idx in idxs {
            filters.push(k.as_str().unwrap().to_string());
            filter_idxs.push(idx.as_i64().unwrap());
        }
    }

    // Collapsed (HW) Filter
    let collapsed_filter = get_collapsed_filter(&filters);
    // Complete (Indexed) Filter PTree
    let ptree = get_ptree(&filters, &filter_idxs);
    // For building parser registry 
    let application_protocols = get_application_protocols(&ptree);

    (ptree, collapsed_filter, application_protocols)
}


// Generate boolean-style filter for packets of interest.
// May be used by online runtime for hw filter.
fn get_collapsed_filter(filters: &Vec<String>) -> String {
    let mut collapsed_filter = String::new(); 
    if !filters.contains(&"".to_string()) {
        collapsed_filter += "(";
        collapsed_filter += filters[0].clone().as_str();
        if filters.len() > 1 {
            for i in 1..filters.len() {
                let filter_str = &filters[i];
                if filter_str == &filters[i - 1] { continue; }
                collapsed_filter += ") or (";
                collapsed_filter += filter_str.clone().as_str();
            }
        }
        collapsed_filter += ")";
    }
    // Displays the collapsed (Boolean) trie during compilation.
    let collapsed_ptree = Filter::from_str(&collapsed_filter, false, 0)
                                                .expect(&format!("Failed to generate collapsed filter: {}", &collapsed_filter))
                                                .to_ptree(0);
    println!("Collapsed Filter:\n{}", collapsed_ptree);

    collapsed_filter
}

fn get_ptree(filters: &Vec<String>, filter_idxs: &Vec<i64>) -> PTree {
    let filter = Filter::from_str(&filters[0], false, filter_idxs[0] as usize)
                                        .expect(&format!("Failed to generate filter: {}", &filters[0]));
    let mut ptree = filter.to_ptree(0);
    for i in 1..filters.len() {
        let filter = Filter::from_str(&filters[i], false, filter_idxs[i] as usize)
                            .expect(&format!("Failed to generate filter: {}", &filters[i]));
        ptree.add_filter(&filter.get_patterns_flat(), i);
    }

    println!("Complete Filter:\n{}", ptree);

    ptree

}

pub(crate) fn get_application_protocols(ptree: &PTree) -> String {
    let mut protocol_names = String::new(); 

    let mut protocols = HashSet::new();
    for pattern in ptree.to_flat_patterns().iter() {
        for predicate in pattern.predicates.iter() {
            if predicate.on_connection() {
                protocols.insert(predicate.get_protocol().to_owned());
            }
        }
    }

    for p in protocols {
        if protocol_names != "" {
            protocol_names += " or ";
        }
        protocol_names += p.name();
    }
    println!("Protocols for parsers:\n- {}", &protocol_names);

    protocol_names
}

// ---- CB Parsing ----
// TODO
// fn callbacks() -> Vec<> ... 
// vec![Box::new(callback1), Box::new(callback2)]

pub(crate) fn get_callbacks_from_config(data_in: Value) -> proc_macro2::TokenStream {
    let callbacks = data_in.get("callbacks")
                                 .expect("Must specify at least one \"callbacks\"");
    let iter = callbacks.as_mapping().unwrap(); 
    let mut callback_names = vec![];
    for (k, v) in iter {
        let idxs = v.as_sequence().unwrap(); 
        for idx in idxs {
            let callback_name = Ident::new(&k.as_str().unwrap(), Span::call_site());
            callback_names.push((
                quote! { Box::new(#callback_name), },
                idx.as_i64().unwrap()
            ));
        }
    }
    callback_names.sort_by(
        |a, b| a.1.cmp(&b.1));
    let mut callbacks = vec![];
    for cb in callback_names {
        callbacks.push(cb.0);
    }

    quote! {
        fn callbacks() -> Vec<Box<dyn Fn(Subscribed)>> {
            vec![#( #callbacks )* ]
        }
    }
}