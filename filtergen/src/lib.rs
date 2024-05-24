use proc_macro::TokenStream;
use quote::quote;
use syn::parse_macro_input;
use retina_core::filter::*;
use retina_core::filter::ptree::*;
use std::collections::{HashMap, HashSet};
use retina_core::protocols::stream::ConnParser;

#[macro_use]
extern crate lazy_static;

mod parse;
mod utils;
mod packet_filter;
mod connection_filter;
mod session_filter;
mod data;

use crate::packet_filter::*;
use crate::connection_filter::*;
use crate::session_filter::*;
use crate::parse::*;
use crate::data::*;

fn get_hw_filter(packet_continue: &HashMap<Actions, Vec<String>>) -> String {
    if packet_continue.is_empty() {
        return "".into();
    }
    let mut ret = String::from("(");
    for (_, v) in packet_continue {
        ret += (v.join(") or (")).as_str();
    }
    ret += ")";
    let _flat_ptree = Filter::from_str(&ret).expect(&format!("Invalid HW filter {}", &ret));
    ret
}

fn filter_subtree(input: &HashMap<Actions, Vec<String>>,  
                  filter_type: FilterType) -> PTree
{
    let mut action_ptrees = vec![];
    for (k, v) in input {

        // Build "pruned" tree for this action
        let mut ptree = PTree::new_empty(filter_type);
        for sub_filter in v {
            let filter = Filter::new(&sub_filter, filter_type, 
                                             k, 0).expect(
                format!("Could not parse filter {}", sub_filter).as_str()
            );
            ptree.build_tree(&filter.get_patterns_flat(), k, 0);
        }
        ptree.prune_branches();
        action_ptrees.push((ptree.to_flat_patterns(), k.clone()));
    }

    let mut ptree = PTree::new_empty(filter_type);
    for (patterns, actions) in action_ptrees {
        ptree.add_filter(
            &patterns,
            &actions,
            0
        );
    }

    // No need to update parsers here, as deliver filters will encompass
    ptree.mark_mutual_exclusion();
    println!("{}", ptree);
    ptree

}

fn deliver_subtree(input: &HashMap<usize, String>,  
                   filter_type: FilterType,
                   parsers: &mut HashSet<&'static str>) -> PTree
{
    let mut ptrees = vec![];
    for (k, v) in input {
        // Build "pruned" tree for this action
        let filter = Filter::new(v, filter_type, 
                                                        &Actions::new(), *k)
                                                        .expect(&format!("Failed to parse filter {}", v));

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

    if !matches!(filter_type, FilterType::Deliver(FilterLayer::PacketDeliver)) {
        for (_, s) in input {
            parsers.extend(ConnParser::requires_parsing(s));
        }
    }

    ptree.mark_mutual_exclusion();
    println!("{}", ptree);
    ptree

}

#[proc_macro_attribute]
pub fn subscription(args: TokenStream, input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as syn::ItemFn);
    let inp_file = parse_macro_input!(args as syn::LitStr).value();
    let config = ConfigBuilder::from_file(&inp_file);
    let mut statics: Vec<proc_macro2::TokenStream> = vec![];

    let mut parsers = HashSet::new();

    if !config.packet_deliver.is_empty() {
        panic!("Packet_deliver not implemented");
    }

    let packet_cont_ptree = filter_subtree(&config.packet_continue, 
                                        FilterType::Action(FilterLayer::Packet));
    let packet_continue = gen_packet_filter(&packet_cont_ptree, &mut statics, false);

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
                FilterType::Deliver(FilterLayer::ConnectionDeliver), &mut parsers);
            gen_connection_filter(&conn_deliver_ptree, &mut statics, true)
        }
    };
    let session_deliver_filter = match config.session_deliver.is_empty() {
        true => { quote! {} },
        false => {
            let session_deliver_ptree = deliver_subtree(&config.session_deliver, 
                FilterType::Deliver(FilterLayer::SessionDeliver), &mut parsers);
            gen_session_filter(&session_deliver_ptree, &mut statics, true)
        }
    };

    // TODO print something for tracked data
    let mut tracked_data = TrackedDataBuilder::new(config.datatypes);
    tracked_data.build();

    let subscribed_data = tracked_data.subscribed_enum();
    let subscribable = tracked_data.subscribable_wrapper();
    let tracked = tracked_data.tracked();


    let filter_str = get_hw_filter(&config.packet_continue); // Packet-level keep/drop filter
    let app_protocols = parsers.into_iter().collect::<Vec<_>>().join(" or ");
    
    let lazy_statics = if statics.is_empty() {
        quote! {}
    } else {
        quote! {
            lazy_static::lazy_static! {
                #( #statics )*
                }
            }
    };

    
    let tst = quote! {

        use retina_datatypes::*;

        #subscribed_data

        #subscribable

        #tracked

        #lazy_statics

        pub(super) fn filter() -> retina_core::filter::FilterFactory<TrackedWrapper> {

            fn packet_continue(mbuf: &retina_core::Mbuf) -> retina_core::filter::Actions {
                // tmp
                #packet_continue
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

            fn session_deliver(session: std::rc::Rc<Session>, 
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