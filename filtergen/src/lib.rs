use proc_macro::TokenStream;
use quote::quote;
use syn::parse_macro_input;
use retina_core::filter::*;
use retina_core::filter::{ptree::*, ptree_flat::*, actions::*};
use std::collections::HashMap;

mod utils;
mod packet_filter;
mod connection_filter;
mod session_filter;

use crate::packet_filter::*;
use crate::connection_filter::*;
use crate::session_filter::*;

fn filter_subtree(input: &HashMap<Actions, Vec<&str>>,  
                  filter_type: FilterType) -> PTree
{
    let mut action_ptrees = vec![];
    for (k, v) in input {

        // Build "pruned" tree for this action
        let mut flat_ptree = FlatPTree::new_empty();
        for sub_filter in v {
            let filter = Filter::from_str(sub_filter).expect(
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

fn deliver_subtree(input: &HashMap<&str, usize>,  
                   filter_type: FilterType) -> PTree
{
    let mut ptrees = vec![];
    for (k, v) in input {
        // Build "pruned" tree for this action
        let filter = Filter::from_str(*k).expect(
            format!("Could not parse filter {}", k).as_str()
        );
        ptrees.push(
            (filter.get_patterns_flat(), *v)
        );
    }

    let mut ptree = PTree::new_empty(filter_type);
    let mut actions_empty = Actions::new();
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
    let mut statics: Vec<proc_macro2::TokenStream> = vec![];

    ///// TMP - sample data /////
    // packet_continue
    let pkt_continue = HashMap::from(
        [
            ("ipv4 and tcp", Packet::Track)
        ]
    );
    // packet_filter
    let packet_filter = HashMap::from( 
        [
            (
                Actions {
                    data: ActionFlags::ConnDataTrack | ActionFlags::ConnParse | ActionFlags::ConnFilter,
                    terminal_actions: ActionData::none()
                }, 
                vec!["ipv4 and tcp"]
            ),
            (
                Actions {
                    data: ActionFlags::ConnDataTrack.into(),
                    terminal_actions: ActionFlags::ConnDataTrack.into(),
                },
                vec!["ipv4.src_addr = 192.0.0.1", "ipv4.src_addr = 192.0.0.2"]
            ),
        ]
    );

    let packet_ptree = filter_subtree(&packet_filter, 
        FilterType::Action(FilterLayer::Packet));
    
    let packet_filter = gen_packet_filter(&packet_ptree, &mut statics, false);

    // connection_filter
    let connection_filter = HashMap::from( 
        [
            (
                Actions {
                    data: ActionFlags::ConnDataTrack | ActionFlags::SessionParse | ActionFlags::SessionTrack,
                    terminal_actions: ActionFlags::ConnDataTrack | ActionFlags::SessionParse
                },
                vec!["ipv4 and tls", "ipv4.src_addr = 192.0.0.1 and http"]
            ),
        ]
    );
    let conn_ptree = filter_subtree(&connection_filter, 
        FilterType::Action(FilterLayer::Connection));

    let conn_filter = gen_connection_filter(&conn_ptree, &mut statics, false);

    let session_filter = HashMap::from( 
        [
            (
                Actions {
                    data: ActionFlags::ConnDataTrack | ActionFlags::SessionTrack,
                    terminal_actions: ActionFlags::ConnDataTrack | ActionFlags::SessionTrack
                },
                vec!["http.user_agent = \'asdfg\' and ipv4.src_addr = 192.0.0.1"]
            ),
        ]
    );
    let session_ptree = filter_subtree(&session_filter, 
        FilterType::Action(FilterLayer::Session));
    let session_filter = gen_session_filter(&session_ptree, &mut statics, false);

    // conn_deliver
    let conn_deliver = HashMap::from(
        [
            ("ipv4 and tls",
                0
            ),
            ("ipv4.src_addr = 192.0.0.1",
                1
            ),
            ("ipv4.src_addr = 192.0.0.2",
                2
            )
        ]
    );
    let conn_deliver_ptree = deliver_subtree(&conn_deliver, 
        FilterType::Deliver(FilterLayer::ConnectionDeliver));
    let conn_deliver_filter = gen_connection_filter(&conn_deliver_ptree, &mut statics, true);
    
    // \todo figure out how to make not litStr
    let tst = quote! {

        fn packet_continue_tst(mbuf: &retina_core::Mbuf) -> retina_core::filter::PacketActions {
            // tmp
            Packet::Track.into()
        }

        fn packet_filter_tst(mbuf: &retina_core::Mbuf) -> retina_core::filter::Actions {
            #packet_filter
        }

        fn conn_filter_tst(conn: &retina_core::protocols::stream::ConnData) -> retina_core::filter::Actions {
            #conn_filter
        }

        fn session_filter_tst(session: &retina_core::protocols::stream::Session,
                              conn: &retina_core::protocols::stream::ConnData) -> retina_core::filter::actions::Actions 
        {
            #session_filter
        }
        
        fn conn_deliver_tst(conn: &ConnData, tracked: &TrackedWrapper)
        {
            #conn_deliver_filter
        }

        #input
    };
    tst.into()
}