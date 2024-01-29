use proc_macro::TokenStream;
use quote::quote;
use syn::parse_macro_input;
use retina_core::filter::*;
use retina_core::filter::{ptree::*, ptree_flat::*};
use std::collections::HashMap;

mod parse;
mod utils;
mod packet_filter;
mod connection_filter;
mod session_filter;

use crate::packet_filter::*;
use crate::connection_filter::*;
use crate::session_filter::*;
use crate::parse::*;

fn filter_subtree(input: &HashMap<Actions, Vec<String>>,  
                  filter_type: FilterType) -> PTree
{
    let mut action_ptrees = vec![];
    for (k, v) in input {

        // Build "pruned" tree for this action
        let mut flat_ptree = FlatPTree::new_empty();
        for sub_filter in v {
            let filter = Filter::from_str(&sub_filter).expect(
                format!("Could not parse filter {}", sub_filter).as_str()
            );
            flat_ptree.build_tree(&filter.get_patterns_flat());
        }
        flat_ptree.prune_branches();
        action_ptrees.push((flat_ptree.to_flat_patterns(), k.clone()));
    }

    let mut ptree = PTree::new_empty(filter_type);
    for (patterns, actions) in action_ptrees {
        ptree.add_filter(
            &patterns,
            &actions,
            0
        );
    }

    println!("{}", ptree);
    ptree

}

fn deliver_subtree(input: &HashMap<usize, String>,  
                   filter_type: FilterType) -> PTree
{
    let mut ptrees = vec![];
    for (k, v) in input {
        // Build "pruned" tree for this action
        let filter = Filter::from_str(v).expect(
            format!("Could not parse filter {}", v).as_str()
        );
        ptrees.push(
            (filter.get_patterns_flat(), *k)
        );
    }

    let mut ptree = PTree::new_empty(filter_type);
    let actions_empty = Actions::new();
    for (patterns, filter_id) in ptrees {
        ptree.add_filter(
            &patterns,
            &actions_empty,
            filter_id
        );
    }

    println!("{}", ptree);
    ptree

}

#[proc_macro_attribute]
pub fn subscription(args: TokenStream, input: TokenStream) -> TokenStream {
    //let _fp_in = parse_macro_input!(args as syn::LitStr).value(); // \todo
    let input = parse_macro_input!(input as syn::ItemFn);
    let inp_file = parse_macro_input!(args as syn::LitStr).value();
    let config = ConfigBuilder::from_file(&inp_file);
    let mut statics: Vec<proc_macro2::TokenStream> = vec![];

    if !config.packet_continue.is_empty() {
        panic!("Pkt_continue not implemented");
    }
    if !config.packet_deliver.is_empty() {
        panic!("Packet_deliver not implemented");
    }

    let packet_ptree = filter_subtree(&config.packet_filter, 
        FilterType::Action(FilterLayer::Packet));
    let packet_filter = gen_packet_filter(&packet_ptree, &mut statics, false);
    
    let conn_filter = match config.connection_filter.is_empty() {
        true => { quote! { Actions::new() } },
        false => { 
            let conn_ptree = filter_subtree(&config.connection_filter, 
                FilterType::Action(FilterLayer::Connection));
            gen_connection_filter(&conn_ptree, &mut statics, false)
        }
    };
    
    let session_filter = match config.session_filter.is_empty() {
        true => { quote! { Actions::new() } },
        false => {
            let session_ptree = filter_subtree(&config.session_filter, 
                FilterType::Action(FilterLayer::Session));
            gen_session_filter(&session_ptree, &mut statics, false)
        }
    };
    let conn_deliver_filter = match config.connection_deliver.is_empty() {
        true => { quote! {} },
        false => { 
            let conn_deliver_ptree = deliver_subtree(&config.connection_deliver, 
                FilterType::Deliver(FilterLayer::ConnectionDeliver));
            gen_connection_filter(&conn_deliver_ptree, &mut statics, true)
        }
    };
    let session_deliver_filter = match config.session_deliver.is_empty() {
        true => { quote! {} },
        false => {
            let session_deliver_ptree = deliver_subtree(&config.session_deliver, 
                FilterType::Deliver(FilterLayer::ConnectionDeliver));
            gen_connection_filter(&session_deliver_ptree, &mut statics, true)
        }
    };

    // TMP - TODOTR 
    // Could be HW filter?
    let filter_str = "";
    let app_protocols = "tls";
    
    let tst = quote! {

        pub(super) fn filter() -> retina_core::filter::FilterFactory<TrackedWrapper> {

            fn packet_continue(mbuf: &retina_core::Mbuf) -> retina_core::filter::PacketActions {
                // tmp
                Packet::Track.into()
            }

            fn packet_filter(mbuf: &retina_core::Mbuf) -> retina_core::filter::Actions {
                #packet_filter
            }

            fn connection_filter(conn: &retina_core::protocols::stream::ConnData) -> retina_core::filter::Actions {
                #conn_filter
            }

            fn session_filter(session: &retina_core::protocols::stream::Session,
                                conn: &retina_core::protocols::stream::ConnData) -> retina_core::filter::actions::Actions 
            {
                #session_filter
            }

            fn packet_deliver(mbuf: &Mbuf) 
            {
                // tmp
            }
            
            fn connection_deliver(conn: &ConnData, tracked: &TrackedWrapper)
            {
                #conn_deliver_filter
            }

            fn session_deliver(session: &Session, 
                                conn: &ConnData, tracked: &TrackedWrapper)
            {
                #session_deliver_filter
            }

            retina_core::filter::FilterFactory::new(
                #filter_str,
                #app_protocols,
                packet_continue,
                packet_filter,
                connection_filter,
                session_filter,
                packet_deliver, 
                connection_deliver,
                session_deliver,
            )
        }

        #input
    };
    tst.into()
}