use proc_macro::TokenStream;
use quote::quote;
use syn::parse_macro_input;
use retina_core::filter::*;
use retina_core::filter::ptree::*;
use utils::DELIVER;
use std::collections::HashSet;
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

fn get_hw_filter(packet_continue: &PTree) -> String {
    let ret = packet_continue.to_filter_string();
    let _flat_ptree = Filter::from_str(&ret).expect(&format!("Invalid HW filter {}", &ret));
    ret
}

fn filter_subtree(input: &SubscriptionConfig,  
                  filter_type: FilterType) -> PTree
{
    let mut ptree = PTree::new_empty(filter_type);
    for sub in &input.subscriptions {
        let filter = Filter::new(
            &sub.filter, 
            filter_type, 
            &sub.datatype, 
            0).expect(
                format!("Could not parse filter {}", &sub.filter).as_str()
            );
        ptree.add_filter(&filter.get_patterns_flat(), &sub.datatype, 0, &String::from(""));
    }
    ptree.prune_branches();
    ptree.mark_mutual_exclusion();
    println!("{}", ptree);
    ptree
}

fn deliver_subtree(input: &SubscriptionConfig,  
                   filter_type: FilterType,
                   parsers: &mut HashSet<&'static str>) -> PTree
{
    let mut ptree = PTree::new_empty(filter_type);

    for i in 0..input.subscriptions.len() {
        let spec = &input.subscriptions[i];
        let filter = Filter::new(&spec.filter, filter_type, &spec.datatype, i)
                     .expect(&format!("Failed to parse filter {}", spec.filter));
        
        let patterns = filter.get_patterns_flat();
        ptree.add_filter(
            &patterns,
            &spec.datatype,
            i,
            &String::from(format!("{}({})", spec.callback, spec.datatype_str))
        );
        if !matches!(filter_type, FilterType::Deliver(FilterLayer::Packet)) {
            parsers.extend(ConnParser::requires_parsing(&spec.filter));
        }
        DELIVER.lock().unwrap().insert(i, spec.clone());
    }

    ptree.prune_branches();
    ptree.mark_mutual_exclusion();
    println!("{}", ptree);
    ptree

}

#[proc_macro_attribute]
pub fn subscription(args: TokenStream, _input: TokenStream) -> TokenStream {
    let inp_file = parse_macro_input!(args as syn::LitStr).value();
    let config = SubscriptionConfig::from_file(&inp_file);
    let mut statics: Vec<proc_macro2::TokenStream> = vec![];

    let mut parsers = HashSet::new();

    let packet_cont_ptree = filter_subtree(&config, FilterType::Action(FilterLayer::PacketContinue));

    let packet_continue = gen_packet_filter(&packet_cont_ptree, &mut statics, false);

    let packet_ptree = filter_subtree(&config, 
        FilterType::Action(FilterLayer::Packet));
    let packet_filter = gen_packet_filter(&packet_ptree, &mut statics, false);
    
    let conn_ptree = filter_subtree(&config, 
        FilterType::Action(FilterLayer::Connection)); 
    let conn_filter = gen_connection_filter(&conn_ptree, &mut statics, false);

    let session_ptree = filter_subtree(&config, 
        FilterType::Action(FilterLayer::Session));
    let session_filter = gen_session_filter(&session_ptree, &mut statics, false);
    
    let conn_deliver_ptree = deliver_subtree(&config, 
                FilterType::Deliver(FilterLayer::Connection), &mut parsers);
    let conn_deliver_filter = gen_connection_filter(&conn_deliver_ptree, &mut statics, true);

    let session_deliver_ptree = deliver_subtree(&config, 
                FilterType::Deliver(FilterLayer::Session), &mut parsers);
    let session_deliver_filter = gen_session_filter(&session_deliver_ptree, &mut statics, true);

    // TODO print something for tracked data
    let mut tracked_data = TrackedDataBuilder::new(&config);

    let subscribed_data = tracked_data.subscribed_enum();
    let subscribable = tracked_data.subscribable_wrapper();
    let tracked = tracked_data.tracked();


    let filter_str = get_hw_filter(&packet_cont_ptree); // Packet-level keep/drop filter
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

    };
    tst.into()
}