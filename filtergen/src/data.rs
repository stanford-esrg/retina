use retina_datatypes::*;
use std::collections::HashSet;
use proc_macro2::{Ident, Span};
use heck::CamelCase;

use quote::quote;

/// The abstraction level of a subscribable type
/// Used at compile-time to determine actions
#[allow(dead_code)]
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Level {
    /// User has requested packets.
    /// If packet-level filter, matched data delivered at packet filter.
    /// Else, packets are buffered until higher-level filter match.
    Packet, 
    /// User has requested all connection data
    /// - Connection will be tracked until termination
    Connection,
    /// User has requested session data
    /// - Sessions will be parsed and delivered
    Session
}

pub(crate) struct TrackedDataBuilder {
    update: Vec<proc_macro2::TokenStream>,
    session_track: Vec<proc_macro2::TokenStream>,
    struct_def: Vec<proc_macro2::TokenStream>,
    new: Vec<proc_macro2::TokenStream>,
    subscribable_enum: Vec<proc_macro2::TokenStream>,
    app_parsers: HashSet<String>,
    subscribed_data: HashSet<String>
}

impl TrackedDataBuilder {
    pub(crate) fn new(subscribed_data: HashSet<String>) -> Self {
        Self {
            update: vec![],
            session_track: vec![],
            struct_def: vec![],
            new: vec![],
            subscribable_enum: vec![],
            app_parsers: HashSet::new(),
            subscribed_data
        }
    }

    pub(crate) fn build(&mut self) {
        for name in &self.subscribed_data {

            let name_str = name.as_str();
            let name_ident = Ident::new(&name_str, Span::call_site());
            let conn_parsers = CONN_PARSERS.get(name_str)
                                .expect(&format!("Cannot get conn_parsers for {}", name));
            let struct_def = TRACKED_DATA_FIELDS.get(name_str)
                                .expect(&format!("Cannot get tracked_fields for {}", name));
            let field_name = Ident::new(&struct_def.0, Span::call_site());
            let field_type = Ident::new(&struct_def.1, Span::call_site()); 

            let needs_update = NEEDS_UPDATE.get(name_str)
                                     .expect(&format!("Cannot get needs_update for {}", name));
            let needs_session = NEEDS_SESSION_MATCH.get(name_str)
                                    .expect(&format!("Cannot get needs_session for {}", name));
            
            self.struct_def.push(
                quote! { 
                    #field_name : #field_type,
                }
            );
            self.new.push( 
                quote! { #field_name: #field_type::new(), }
            );
            self.subscribable_enum.push(
                quote! { #name_ident(#name_ident), }
            );
            if *needs_update {
                // TODO will a subscription ever want to be able to know if *it* is matching 
                //              before the deliver phase? 
                self.update.push(
                    quote! { self.#field_name.update(&pdu, session_id); }
                );
            }
            if *needs_session {
                self.session_track.push(
                    quote! { self.#field_name.session_matched(&session); }
                )
            }
            for c in conn_parsers {
                if let Some(name) = c.name() {
                    self.app_parsers.insert(name);
                } else {
                    panic!("Invalid conn_parsers for {}", name_str);
                }
            }
        }
    }

    pub(crate) fn subscribable_wrapper(&mut self) -> proc_macro2::TokenStream {

        let parsers: Vec<proc_macro2::TokenStream> = 
                std::mem::take(&mut self.app_parsers)
                        .into_iter()
                        .map( |s| {
                            let proto = Ident::new(&s.as_str().to_camel_case(), 
                                                    Span::call_site());
                            let parser = Ident::new(&(s.as_str().to_camel_case() + "Parser"),
                                                    Span::call_site());
                            quote! { ConnParser::#proto(#parser::default()), }
                        } ).collect();
        
        // TODO only include if actually needed
        let packet_deliver = quote! {
            if actions.contains(Packet::Deliver) {
                subscription.deliver_packet(&mbuf);
            }
        }; 

        // TODO only include if actually needed
        let packet_track = quote! {
            if actions.intersects(Packet::Track | Packet::Unsure) {
                if let Ok(ctxt) = L4Context::new(&mbuf) {
                    conn_tracker.process(mbuf, ctxt, subscription);
                }
            }
        };

        quote! {
            pub struct SubscribedWrapper;

            impl Subscribable for SubscribedWrapper {
                type Tracked = TrackedWrapper;
                type SubscribedData = Subscribed;
                fn parsers() -> Vec<ConnParser> {
                    vec![#( #parsers )*]
                }
            
                fn process_packet(
                    mbuf: Mbuf,
                    subscription: &Subscription<Self>,
                    conn_tracker: &mut ConnTracker<Self::Tracked>,
                    actions: PacketActions
                ) {
                    #packet_deliver
                    #packet_track
                }
            } 
        }       
    }

    pub(crate) fn subscribed_enum(&mut self) -> proc_macro2::TokenStream {
        let field_names = std::mem::take(&mut self.subscribable_enum);
        quote! { 
            #[derive(Debug)]
            pub enum Subscribed {
                #( #field_names )*
            }
        }
    }

    pub(crate) fn tracked(&mut self) -> proc_macro2::TokenStream {
        let def = std::mem::take(&mut self.struct_def);
        let update = std::mem::take(&mut self.update);
        let new = std::mem::take(&mut self.new);
        let session_track = std::mem::take(&mut self.session_track);
        quote! {
            pub struct TrackedWrapper {
                five_tuple: FiveTuple,
                #( #def )*
            }

            impl Trackable for TrackedWrapper {
                type Subscribed = SubscribedWrapper;
    
                fn new(five_tuple: FiveTuple) -> Self {

                    Self {
                        five_tuple,
                        #( #new )*
                    }
                }

                fn update(&mut self, 
                        pdu: L4Pdu, 
                        session_id: Option<usize>, 
                        actions: &ActionData)
                {
                    #( #update )*
                }
            
                fn deliver_session(&mut self, session: Session, 
                                subscription: &Subscription<Self::Subscribed>,
                                actions: &ActionData, conn_data: &ConnData)
                { 
                    // TODO only if actually needed
                    if actions.contains(ActionFlags::SessionTrack) {
                        #( #session_track )*
                    }
                    if actions.contains(ActionFlags::SessionDeliver) {
                        subscription.deliver_session(&session, &conn_data, &self);
                    }
                }

                fn deliver_conn(&mut self, 
                                subscription: &Subscription<Self::Subscribed>,
                                actions: &ActionData, conn_data: &ConnData)
                {
                    subscription.deliver_conn(conn_data, self);
                }
                
                fn five_tuple(&self) -> FiveTuple {
                    self.five_tuple
                }
            }
        }
    }

}