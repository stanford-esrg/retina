use proc_macro2::{Ident, Span};
use retina_core::protocols::stream::ConnParser;
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
            let name = &spec.datatypes[0].as_str;
            let type_name = Ident::new(name, Span::call_site());
            let field_name = Ident::new(&name.to_lowercase(), Span::call_site());

            self.stream_protocols
                .extend(ConnParser::requires_parsing(&spec.filter));
            if self.datatypes.contains(name) {
                continue;
            }
            self.datatypes.insert(name);
            self.stream_protocols.extend(&spec.datatypes[0].stream_protos);

            if matches!(spec.datatypes[0].level, Level::Session)
                || matches!(spec.datatypes[0].level, Level::Packet)
            {
                // Data built directly from packet or session isn't tracked
                continue;
            }

            self.struct_def.push(quote! {
                #field_name : #type_name,
            });
            self.new
                .push(quote! { #field_name: #type_name::new(&five_tuple), });

            if spec.datatypes[0].needs_update {
                // TODO will a subscription ever want to be able to know if *it* is matching
                //              before the deliver phase?
                self.update
                    .push(quote! { self.#field_name.update(pdu, session_id); });
            }
        }
        self.print();
    }

    pub(crate) fn print(&self) {
        println!("Tracked {{");
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

        let mut conn_parsers = vec![];
        for datatype in &self.stream_protocols {
            conn_parsers.push(quote! { #datatype, });
        }

        quote! {
            pub struct TrackedWrapper {
                five_tuple: FiveTuple,
                core_id: u32,
                sessions: Vec<Session>,
                mbufs: Vec<Mbuf>,
                #( #def )*
            }

            impl Trackable for TrackedWrapper {
                type Subscribed = SubscribedWrapper;

                fn new(five_tuple: FiveTuple, core_id: u32) -> Self {

                    Self {
                        five_tuple,
                        core_id,
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

                fn five_tuple(&self) -> FiveTuple {
                    self.five_tuple
                }

                fn sessions(&self) -> &Vec<Session> {
                    &self.sessions
                }

                fn track_session(&mut self, session: Session) {
                    self.sessions.push(session);
                }

                fn core_id(&self) -> u32 {
                    self.core_id
                }

                fn parsers() -> retina_core::protocols::stream::ParserRegistry {
                    retina_core::protocols::stream::ParserRegistry::from_strings(vec![ #( #conn_parsers )* ])
                }
            }
        }
    }
}
