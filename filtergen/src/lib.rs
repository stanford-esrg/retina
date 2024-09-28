use proc_macro::TokenStream;
use quote::quote;
use retina_core::filter::ptree::*;
use retina_core::filter::*;
use syn::parse_macro_input;
use utils::DELIVER;

#[macro_use]
extern crate lazy_static;

mod data;
mod deliver_filter;
mod packet_filter;
mod parse;
mod proto_filter;
mod session_filter;
mod utils;

use crate::data::*;
use crate::deliver_filter::gen_deliver_filter;
use crate::packet_filter::gen_packet_filter;
use crate::parse::*;
use crate::proto_filter::gen_proto_filter;
use crate::session_filter::gen_session_filter;

fn get_hw_filter(packet_continue: &PTree) -> String {
    let ret = packet_continue.to_filter_string();
    let _flat_ptree =
        Filter::new(&ret).unwrap_or_else(|err| panic!("Invalid HW filter {}: {:?}", &ret, err));
    ret
}

fn filter_subtree(input: &SubscriptionConfig, filter_layer: FilterLayer) -> PTree {
    let mut ptree = PTree::new_empty(filter_layer);

    for i in 0..input.subscriptions.len() {
        let spec = &input.subscriptions[i];
        let filter = Filter::new(&spec.filter)
            .unwrap_or_else(|err| panic!("Failed to parse filter {}: {:?}", spec.filter, err));

        let patterns = filter.get_patterns_flat();
        ptree.add_filter(&patterns, &spec, i);
        DELIVER.lock().unwrap().insert(i, spec.clone());
    }

    ptree.collapse();
    println!("{}", ptree);
    ptree
}

#[proc_macro_attribute]
pub fn subscription(args: TokenStream, input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as syn::ItemFn);

    let inp_file = parse_macro_input!(args as syn::LitStr).value();
    let config = SubscriptionConfig::from_file(&inp_file);
    let mut statics: Vec<proc_macro2::TokenStream> = vec![];

    let packet_cont_ptree = filter_subtree(&config, FilterLayer::PacketContinue);
    let packet_continue = gen_packet_filter(
        &packet_cont_ptree,
        &mut statics,
        FilterLayer::PacketContinue,
    );

    let packet_ptree = filter_subtree(&config, FilterLayer::Packet);
    let packet_filter = gen_packet_filter(&packet_ptree, &mut statics, FilterLayer::Packet);

    let conn_ptree = filter_subtree(&config, FilterLayer::Protocol);
    let proto_filter = gen_proto_filter(&conn_ptree, &mut statics);

    let session_ptree = filter_subtree(&config, FilterLayer::Session);
    let session_filter = gen_session_filter(&session_ptree, &mut statics);

    let conn_deliver_ptree = filter_subtree(&config, FilterLayer::ConnectionDeliver);
    let conn_deliver_filter = gen_deliver_filter(
        &conn_deliver_ptree,
        &mut statics,
        FilterLayer::ConnectionDeliver,
    );
    let packet_deliver_ptree = filter_subtree(&config, FilterLayer::PacketDeliver);
    let packet_deliver_filter = gen_deliver_filter(
        &packet_deliver_ptree,
        &mut statics,
        FilterLayer::PacketDeliver,
    );

    let mut tracked_data = TrackedDataBuilder::new(&config);
    let subscribable = tracked_data.subscribable_wrapper();
    let tracked = tracked_data.tracked();

    let filter_str = get_hw_filter(&packet_cont_ptree); // Packet-level keep/drop filter

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
        use retina_core::filter::actions::*;
        use retina_core::subscription::{Trackable, Subscribable};

        #subscribable

        #tracked

        #lazy_statics

        pub fn filter() -> retina_core::filter::FilterFactory<TrackedWrapper> {

            fn packet_continue(mbuf: &retina_core::Mbuf,
                               core_id: &retina_core::CoreId) -> Actions {
                #packet_continue
            }

            fn packet_filter(mbuf: &retina_core::Mbuf) -> Actions {
                #packet_filter
            }

            fn protocol_filter(conn: &retina_core::protocols::ConnData,
                               tracked: &TrackedWrapper) -> Actions {
                #proto_filter
            }

            fn session_filter(session: &retina_core::protocols::Session,
                              conn: &retina_core::protocols::ConnData,
                              tracked: &TrackedWrapper) -> Actions
            {
                #session_filter
            }

            fn packet_deliver(mbuf: &retina_core::Mbuf,
                              conn: &retina_core::protocols::ConnData,
                              tracked: &TrackedWrapper)
            {
                #packet_deliver_filter
            }

            fn connection_deliver(conn: &retina_core::protocols::ConnData,
                                  tracked: &TrackedWrapper)
            {
                #conn_deliver_filter
            }

            retina_core::filter::FilterFactory::new(
                #filter_str,
                packet_continue,
                packet_filter,
                protocol_filter,
                session_filter,
                packet_deliver,
                connection_deliver,
            )
        }

        #input

    };
    tst.into()
}
