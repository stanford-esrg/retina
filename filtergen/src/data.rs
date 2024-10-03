use proc_macro2::{Ident, Span};
use retina_core::filter::{ptree::FilterLayer, Level, SubscriptionSpec};
use retina_core::protocols::stream::ConnParser;
use retina_datatypes::*;
use std::collections::HashSet;

use quote::quote;

use crate::SubscriptionConfig;

pub(crate) struct TrackedDataBuilder {
    update: Vec<proc_macro2::TokenStream>,
    struct_def: Vec<proc_macro2::TokenStream>,
    new: Vec<proc_macro2::TokenStream>,
    clear: Vec<proc_macro2::TokenStream>,
    stream_protocols: HashSet<&'static str>,
    datatypes: HashSet<&'static str>,
}

impl TrackedDataBuilder {
    pub(crate) fn new(subscribed_data: &SubscriptionConfig) -> Self {
        let mut ret = Self {
            update: vec![],
            struct_def: vec![],
            new: vec![],
            clear: vec![],
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
                if self.datatypes.contains(name) || name == *FILTER_STR {
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
                self.new.push(quote! { #field_name: #type_name::new(pdu), });

                if datatype.needs_update {
                    self.clear.push(quote! { self.#field_name.clear(); });
                    self.update
                        .push(quote! { self.#field_name.update(pdu, reassembled); });
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
        let clear = std::mem::take(&mut self.clear);

        let mut conn_parsers: Vec<proc_macro2::TokenStream> = vec![];
        for datatype in &self.stream_protocols {
            conn_parsers.push(quote! { #datatype, });
        }

        quote! {
            pub struct TrackedWrapper {
                sessions: Vec<retina_core::protocols::Session>,
                mbufs: Vec<retina_core::Mbuf>,
                core_id: retina_core::CoreId,
                #( #def )*
            }

            impl Trackable for TrackedWrapper {
                type Subscribed = SubscribedWrapper;

                fn new(pdu: &retina_core::L4Pdu,
                       core_id: retina_core::CoreId) -> Self {
                    Self {
                        sessions: vec![],
                        mbufs: vec![],
                        core_id,
                        #( #new )*
                    }
                }

                fn update(&mut self,
                        pdu: &retina_core::L4Pdu,
                        reassembled: bool)
                {
                    #( #update )*
                }

                fn core_id(&self) -> &retina_core::CoreId {
                    &self.core_id
                }

                fn track_packet(&mut self, mbuf: retina_core::Mbuf) {
                    self.mbufs.push(mbuf);
                }

                fn packets(&self) -> &Vec<retina_core::Mbuf> {
                    &self.mbufs
                }

                fn drain_packets(&mut self) {
                    self.mbufs = vec![];
                }

                fn clear(&mut self) {
                    self.drain_packets();
                    self.sessions = vec![];
                    #( #clear )*
                }

                fn sessions(&self) -> &Vec<retina_core::protocols::Session> {
                    &self.sessions
                }

                fn track_session(&mut self, session: retina_core::protocols::Session) {
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
// Only multi-parameter packet-level subscription supported is a packet datatype + retina_core::CoreId
pub(crate) fn build_packet_params(
    spec: &SubscriptionSpec,
    filter_layer: FilterLayer,
) -> (Vec<proc_macro2::TokenStream>, Option<Ident>) {
    let mut type_ident = None;
    let mut params = vec![];
    for datatype in &spec.datatypes {
        if matches!(datatype.level, Level::Packet) {
            params.push(quote! { p });
            type_ident = Some(Ident::new(&datatype.as_str, Span::call_site()));
        }
        // Spacial cases - can't be extracted from the packet data, so are
        // permitted in packet-layer callbacks

        // Literal string in code
        else if datatype.as_str == *FILTER_STR {
            params.push(retina_datatypes::FilterStr::from_subscription(&spec));
        }
        // passed as a parameter to the packet filter, accessed directly
        // or pulled from directly tracked data
        else if datatype.as_str == "CoreId" {
            if matches!(filter_layer, FilterLayer::PacketContinue) {
                params.push(quote! { core_id });
            } else {
                let accessor = Ident::new(
                    &DIRECTLY_TRACKED.get("CoreId").unwrap().to_lowercase(),
                    Span::call_site(),
                );
                params.push(quote! { tracked.#accessor() });
            }
        } else {
            panic!("Invalid datatype in packet callback: {:?}", datatype);
        }
    }

    (params, type_ident)
}

pub(crate) fn build_packet_callback(
    spec: &SubscriptionSpec,
    filter_layer: FilterLayer,
) -> proc_macro2::TokenStream {
    let callback = Ident::new(&spec.callback, Span::call_site());
    let (params, type_ident) = build_packet_params(spec, filter_layer);

    let condition = match type_ident {
        Some(type_ident) => quote! { let Some(p) = #type_ident::from_mbuf(mbuf) },
        None => quote! { true },
    };

    return match filter_layer {
        // Deliver packet directly
        FilterLayer::PacketContinue | FilterLayer::PacketDeliver => {
            quote! {
                if #condition {
                    #callback(#( #params ),*);
                }
            }
        }
        _ => {
            // Drain existing tracked packets
            quote! {
                for mbuf in tracked.packets() {
                    if #condition {
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
        if datatype.as_str == *FILTER_STR {
            params.push(retina_datatypes::FilterStr::from_subscription(&spec));
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
        } else if matches!(datatype.level, Level::Session)
            && matches!(filter_layer, FilterLayer::ConnectionDeliver)
        {
            let type_ident = Ident::new(&datatype.as_str, Span::call_site());
            condition =
                quote! { if let Some(s) = #type_ident::from_sessionlist(tracked.sessions()) };
            params.push(quote! { s });
        } else {
            panic!(
                "{:?} datatype in {:?} subscription with delivery at {:?}",
                datatype.level, spec.level, filter_layer
            );
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
