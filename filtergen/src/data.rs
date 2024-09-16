use proc_macro2::{Ident, Span};
use retina_core::filter::{ptree::FilterLayer, SubscriptionSpec};
use retina_core::protocols::stream::ConnParser;
use retina_datatypes::typedefs::DIRECTLY_TRACKED;
use std::collections::HashSet;

use quote::quote;

use crate::SubscriptionConfig;

use retina_core::filter::Level;

pub(crate) struct TrackedDataBuilder {
    update: Vec<proc_macro2::TokenStream>,
    struct_def: Vec<proc_macro2::TokenStream>,
    new: Vec<proc_macro2::TokenStream>,
    stream_protocols: HashSet<&'static str>,
    datatypes: HashSet<&'static str>,
}

impl TrackedDataBuilder {
    pub(crate) fn new(subscribed_data: &SubscriptionConfig) -> Self {
        let mut ret = Self {
            update: vec![],
            struct_def: vec![],
            new: vec![],
            stream_protocols: HashSet::new(),
            datatypes: HashSet::new(),
        };
        ret.build(subscribed_data);
        ret
    }

    pub(crate) fn build(&mut self, subscribed_data: &SubscriptionConfig) {
        for spec in &subscribed_data.subscriptions {
            self.stream_protocols
                .extend(ConnParser::requires_parsing(&spec.filter));
            for datatype in &spec.datatypes {
                let name = datatype.as_str;
                if self.datatypes.contains(name) {
                    continue;
                }
                self.datatypes.insert(name);
                self.stream_protocols.extend(&datatype.stream_protos);
                if matches!(datatype.level, Level::Session)
                    || matches!(datatype.level, Level::Packet)
                    || DIRECTLY_TRACKED.contains_key(name)
                {
                    // Data built directly from packet or session isn't tracked
                    continue;
                }
                let type_name = Ident::new(name, Span::call_site());
                let field_name = Ident::new(&name.to_lowercase(), Span::call_site());

                self.struct_def.push(quote! {
                    #field_name : #type_name,
                });
                self.new
                    .push(quote! { #field_name: #type_name::new(five_tuple, &core_id), });

                if datatype.needs_update {
                    self.update
                        .push(quote! { self.#field_name.update(pdu, session_id); });
                }
            }
        }
        self.print();
    }

    pub(crate) fn print(&self) {
        println!("Datatypes {{");
        for dt in &self.datatypes {
            println!("  {},", dt,);
        }
        println!("}}\n");
        println!("Parsers {{");
        for proto in &self.stream_protocols {
            println!("  {},", proto);
        }
        println!("}}\n");
    }

    pub(crate) fn subscribable_wrapper(&mut self) -> proc_macro2::TokenStream {
        quote! {
            pub struct SubscribedWrapper;
            impl Subscribable for SubscribedWrapper {
                type Tracked = TrackedWrapper;
            }
        }
    }

    pub(crate) fn tracked(&mut self) -> proc_macro2::TokenStream {
        let def = std::mem::take(&mut self.struct_def);
        let update = std::mem::take(&mut self.update);
        let new = std::mem::take(&mut self.new);

        let mut conn_parsers: Vec<proc_macro2::TokenStream> = vec![];
        for datatype in &self.stream_protocols {
            conn_parsers.push(quote! { #datatype, });
        }

        quote! {
            pub struct TrackedWrapper {
                sessions: Vec<Session>,
                mbufs: Vec<Mbuf>,
                #( #def )*
            }

            impl Trackable for TrackedWrapper {
                type Subscribed = SubscribedWrapper;

                fn new(five_tuple: &retina_core::conntrack::conn_id::FiveTuple,
                       core_id: retina_core::lcore::CoreId) -> Self {

                    Self {
                        sessions: vec![],
                        mbufs: vec![],
                        #( #new )*
                    }
                }

                fn update(&mut self,
                        pdu: &L4Pdu,
                        session_id: Option<usize>)
                {
                    #( #update )*
                }

                fn track_packet(&mut self, mbuf: Mbuf) {
                    self.mbufs.push(mbuf);
                }

                fn packets(&self) -> &Vec<Mbuf> {
                    &self.mbufs
                }

                fn drain_packets(&mut self) {
                    self.mbufs = vec![];
                }

                fn sessions(&self) -> &Vec<Session> {
                    &self.sessions
                }

                fn track_session(&mut self, session: Session) {
                    self.sessions.push(session);
                }

                fn parsers() -> retina_core::protocols::stream::ParserRegistry {
                    retina_core::protocols::stream::ParserRegistry::from_strings(vec![ #( #conn_parsers )* ])
                }
            }
        }
    }
}

// Build parameters for a packet-level subscription
// Only multi-parameter packet-level subscription supported is a packet datatype + CoreId
pub(crate) fn build_packet_params(
    spec: &SubscriptionSpec,
    filter_layer: FilterLayer,
) -> Vec<proc_macro2::TokenStream> {
    if spec.datatypes.len() > 1 {
        assert!(
            spec.datatypes.len() == 2
                && spec
                    .datatypes
                    .iter()
                    .filter(|d| d.as_str == "CoreId")
                    .count()
                    == 1
                && spec
                    .datatypes
                    .iter()
                    .filter(|d| matches!(d.level, Level::Packet))
                    .count()
                    == 1
        );
    }

    let field_ident = Ident::new("coreid", Span::call_site());

    let mut params = vec![quote! { p }];
    if spec.datatypes.len() > 1 {
        params.push(match filter_layer {
            FilterLayer::PacketContinue => {
                quote! { #field_ident }
            }
            _ => {
                quote! { &tracked.#field_ident }
            }
        });
    }

    params
}

pub(crate) fn build_packet_callback(
    spec: &SubscriptionSpec,
    filter_layer: FilterLayer,
) -> proc_macro2::TokenStream {
    // Single packet datatype OR packet datatype + Core ID
    assert!(
        spec.datatypes.len() == 1
            || (spec.datatypes.len() == 2
                && spec
                    .datatypes
                    .iter()
                    .filter(|d| d.as_str == "CoreId")
                    .count()
                    == 1
                && spec
                    .datatypes
                    .iter()
                    .filter(|d| matches!(d.level, Level::Packet))
                    .count()
                    == 1)
    );

    let callback = Ident::new(&spec.callback, Span::call_site());
    let type_ident = Ident::new(&spec.datatypes[0].as_str, Span::call_site());
    let params = build_packet_params(spec, filter_layer);

    return match filter_layer {
        // Deliver packet directly
        FilterLayer::PacketContinue | FilterLayer::PacketDeliver => {
            quote! {
                if let Some(p) = #type_ident::from_mbuf(mbuf) {
                    #callback(#( #params ),*);
                }
            }
        }
        _ => {
            // Drain existing tracked packets
            quote! {
                for mbuf in tracked.packets() {
                    if let Some(p) = #type_ident::from_mbuf(mbuf) {
                        #callback(#( #params ),*);
                    }
                }
            }
        }
    };
}

pub(crate) fn build_callback(
    spec: &SubscriptionSpec,
    filter_layer: FilterLayer,
    session_loop: bool,
) -> proc_macro2::TokenStream {
    let callback = Ident::new(&spec.callback, Span::call_site());
    let mut params = vec![];
    let mut condition = quote! {};

    for datatype in &spec.datatypes {
        if DIRECTLY_TRACKED.contains_key(datatype.as_str) {
            let accessor = Ident::new(
                DIRECTLY_TRACKED.get(&datatype.as_str).unwrap(),
                Span::call_site(),
            );
            params.push(quote! { tracked.#accessor() });
            continue;
        }
        if matches!(datatype.level, Level::Session) && matches!(filter_layer, FilterLayer::Session)
        {
            let type_ident = Ident::new(&datatype.as_str, Span::call_site());
            condition = quote! { if let Some(s) = #type_ident::from_session(session) };
            params.push(quote! { s });
        } else if matches!(datatype.level, Level::Static | Level::Connection) {
            let tracked_field: Ident =
                Ident::new(&datatype.as_str.to_lowercase(), Span::call_site());
            params.push(quote! { &tracked.#tracked_field });
        } else {
            panic!("Packet-level datatype in non-packet subscription");
        }
    }

    let break_early = match session_loop {
        true => quote! { break; },
        false => quote! {},
    };

    quote! {
        #condition {
            #callback(#( #params ),*);
            #break_early
        }
    }
}
