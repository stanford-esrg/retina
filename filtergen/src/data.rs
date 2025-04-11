use proc_macro2::{Ident, Span};
use retina_core::filter::{ptree::FilterLayer, Level, SubscriptionSpec};
use retina_core::protocols::stream::ConnParser;
use retina_datatypes::*;
use std::collections::HashSet;

use quote::quote;

use crate::SubscriptionConfig;

pub(crate) struct TrackedDataBuilder {
    update: Vec<proc_macro2::TokenStream>,
    track_packet: Vec<proc_macro2::TokenStream>,
    struct_def: Vec<proc_macro2::TokenStream>,
    new: Vec<proc_macro2::TokenStream>,
    clear: Vec<proc_macro2::TokenStream>,
    pkts_clear: Vec<proc_macro2::TokenStream>,
    streaming_cbs: Vec<proc_macro2::TokenStream>,
    stream_protocols: HashSet<&'static str>,
    datatypes: HashSet<&'static str>,
    num_streaming: usize,
}

impl TrackedDataBuilder {
    pub(crate) fn new(subscribed_data: &SubscriptionConfig) -> Self {
        let mut ret = Self {
            update: vec![],
            track_packet: vec![],
            struct_def: vec![],
            new: vec![],
            clear: vec![],
            pkts_clear: vec![],
            streaming_cbs: vec![],
            stream_protocols: HashSet::new(),
            datatypes: HashSet::new(),
            num_streaming: 0,
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

                if datatype.needs_packet_track {
                    self.track_packet
                        .push(quote! { self.#field_name.track_packet(pdu, reassembled); });
                    self.pkts_clear.push(quote! { self.#field_name.clear(); });
                }
            }
            if let Level::Streaming(streamtype) = spec.level {
                let field_name = Ident::new(
                    &format!("streaming_{}", self.num_streaming),
                    Span::call_site(),
                );
                self.num_streaming += 1;
                let datatype = spec
                    .datatypes
                    .iter()
                    .find(|d| d.level.can_stream())
                    .unwrap();
                let type_name = Ident::new(datatype.as_str, Span::call_site());
                let stream_type = quote! { #streamtype };

                self.struct_def.push(quote! {
                    #field_name : retina_datatypes::CallbackTimer<#type_name>,
                });
                self.new.push( quote! {
                    #field_name: retina_datatypes::CallbackTimer::<#type_name>::new(#stream_type, pdu),
                });
                self.update.push(quote! {
                    self.#field_name.update(pdu, reassembled);
                });
                // Delivery params take the same form as delivering Connection-level data
                let cb = build_callback(spec, FilterLayer::ConnectionDeliver, false, true);
                self.streaming_cbs.push(quote! {
                    // TODO clean up
                    if self.#field_name.invoke(pdu) {
                        let cont = {
                            let tracked = &self;
                            let mut ret = true;
                            // CB returns `true` if user wants to continue receiving data on this subscription.
                            // By default, continue streaming.
                            #cb // inserts `;`, returns value to `ret`
                            ret
                        };
                        if cont {
                            cont_streaming = true;
                        } else {
                            self.#field_name.unsubscribe();
                        }
                        self.#field_name.clear();
                    } else {
                        // Try again
                        cont_streaming = true;
                    }
                });
                self.clear.push(quote! { self.#field_name.clear(); });
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
        let track_packet = std::mem::take(&mut self.track_packet);
        let new = std::mem::take(&mut self.new);
        let clear = std::mem::take(&mut self.clear);
        let pkts_clear = std::mem::take(&mut self.pkts_clear);
        let streaming_cbs = std::mem::take(&mut self.streaming_cbs);

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

                fn buffer_packet(&mut self, pdu: &retina_core::L4Pdu, actions: &Actions,
                                reassembled: bool) {
                    if !reassembled &&
                        actions.data.intersects(ActionData::PacketCache) {
                        self.mbufs.push(retina_core::Mbuf::new_ref(&pdu.mbuf));
                    }
                    if actions.data.intersects(ActionData::PacketTrack) {
                        #( #track_packet )*
                    }
                }

                // Avoid "unreachable" warning if no streaming callbacks or if cbs always
                // return true/false.
                // #[allow(unreachable_code)]
                fn stream_deliver(&mut self, actions: &mut Actions, pdu: &retina_core::L4Pdu) {
                    let mut cont_streaming = false;
                    #( #streaming_cbs )*
                    // Note - could be cleaner to put action update core?
                    if !cont_streaming {
                        actions.clear_stream_cbs();
                    }
                }

                fn packets(&self) -> &Vec<retina_core::Mbuf> {
                    &self.mbufs
                }

                fn drain_cached_packets(&mut self) {
                    self.mbufs = vec![];
                }

                fn drain_tracked_packets(&mut self) {
                    #( #pkts_clear )*
                }

                fn clear(&mut self) {
                    self.drain_tracked_packets();
                    self.drain_cached_packets();
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
            type_ident = Some(Ident::new(datatype.as_str, Span::call_site()));
        }
        // Spacial cases - can't be extracted from the packet data, so are
        // permitted in packet-layer callbacks

        // Literal string in code
        else if datatype.as_str == *FILTER_STR {
            params.push(retina_datatypes::FilterStr::from_subscription(spec));
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

    match filter_layer {
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
    }
}

pub(crate) fn build_callback(
    spec: &SubscriptionSpec,
    filter_layer: FilterLayer,
    session_loop: bool,
    returns: bool,
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
            params.push(retina_datatypes::FilterStr::from_subscription(spec));
            continue;
        }
        if matches!(datatype.level, Level::Session) && matches!(filter_layer, FilterLayer::Session)
        {
            let type_ident = Ident::new(datatype.as_str, Span::call_site());
            condition = quote! { if let Some(s) = #type_ident::from_session(session) };
            params.push(quote! { s });
        } else if matches!(datatype.level, Level::Static | Level::Connection) {
            let tracked_field: Ident =
                Ident::new(&datatype.as_str.to_lowercase(), Span::call_site());
            params.push(quote! { &tracked.#tracked_field });
        } else if matches!(datatype.level, Level::Session)
            && matches!(filter_layer, FilterLayer::ConnectionDeliver)
        {
            let type_ident = Ident::new(datatype.as_str, Span::call_site());
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
    let returns = match returns {
        true => quote! { ret = },
        false => quote! {},
    };

    quote! {
        #condition {
            #returns #callback(#( #params ),*);
            #break_early
        }
    }
}
