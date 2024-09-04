use proc_macro::TokenStream;
use quote::quote;
use syn::parse_macro_input;
use retina_core::filter::*;
use retina_core::filter::ptree::*;
use utils::DELIVER;

#[macro_use]
extern crate lazy_static;

mod parse;
mod utils;
mod packet_filter;
mod proto_filter;
mod session_filter;
mod deliver_filter;
mod data;

use crate::packet_filter::gen_packet_filter;
use crate::proto_filter::gen_proto_filter;
use crate::session_filter::gen_session_filter;
use crate::deliver_filter::gen_deliver_filter;
use crate::parse::*;
use crate::data::*;

fn get_hw_filter(packet_continue: &PTree) -> String {
    let ret = packet_continue.to_filter_string();
    let _flat_ptree = Filter::new(&ret).unwrap_or_else(|_| panic!("Invalid HW filter {}", &ret));
    ret
}

fn filter_subtree(input: &SubscriptionConfig,
                  filter_layer: FilterLayer) -> PTree
{
    let mut ptree = PTree::new_empty(filter_layer);

    for i in 0..input.subscriptions.len() {
        let spec = &input.subscriptions[i];
        let filter = Filter::new(&spec.filter)
                     .unwrap_or_else(|_| panic!("Failed to parse filter {}", spec.filter));

        let patterns = filter.get_patterns_flat();
        ptree.add_filter(
            &patterns,
            &spec.datatype,
            i,
            &format!("{}({})", spec.callback, spec.datatype_str)
        );
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

    let packet_cont_ptree = filter_subtree(&config, FilterLayer::PacketContinue);
    let packet_continue = gen_packet_filter(&packet_cont_ptree, &mut statics, FilterLayer::PacketContinue);

    let packet_ptree = filter_subtree(&config, FilterLayer::Packet);
    let packet_filter = gen_packet_filter(&packet_ptree, &mut statics, FilterLayer::Packet);

    let conn_ptree = filter_subtree(&config, FilterLayer::Protocol);
    let proto_filter = gen_proto_filter(&conn_ptree, &mut statics);

    let session_ptree = filter_subtree(&config, FilterLayer::Session);
    let session_filter = gen_session_filter(&session_ptree, &mut statics);

    let conn_deliver_ptree = filter_subtree(&config, FilterLayer::ConnectionDeliver);
    let conn_deliver_filter = gen_deliver_filter(&conn_deliver_ptree, &mut statics, FilterLayer::ConnectionDeliver);
    let packet_deliver_ptree = filter_subtree(&config, FilterLayer::PacketDeliver);
    let packet_deliver_filter = gen_deliver_filter(&packet_deliver_ptree, &mut statics, FilterLayer::PacketDeliver);

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
        use retina_core::conntrack::conn_id::FiveTuple;
        use retina_core::conntrack::pdu::L4Pdu;
        use retina_core::memory::mbuf::Mbuf;
        use retina_core::protocols::stream::{Session, ConnData};
        use retina_core::subscription::{Subscribable, Trackable};
        use retina_core::filter::actions::*;

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

            fn protocol_filter(conn: &retina_core::protocols::stream::ConnData,
                               tracked: &TrackedWrapper) -> retina_core::filter::Actions {
                #proto_filter
            }

            fn session_filter(session: &retina_core::protocols::stream::Session,
                              conn: &retina_core::protocols::stream::ConnData,
                              tracked: &TrackedWrapper) -> retina_core::filter::actions::Actions
            {
                #session_filter
            }

            fn packet_deliver(mbuf: &Mbuf, conn: &ConnData, tracked: &TrackedWrapper)
            {
                #packet_deliver_filter
            }

            fn connection_deliver(conn: &ConnData, tracked: &TrackedWrapper)
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

    };
    tst.into()
}