use std::collections::HashSet;
use proc_macro2::{Ident, Span};

use quote::quote;

use crate::SubscriptionConfig;

use retina_core::filter::datatypes::Level;

pub(crate) struct TrackedDataBuilder {
    update: Vec<proc_macro2::TokenStream>,
    struct_def: Vec<proc_macro2::TokenStream>,
    new: Vec<proc_macro2::TokenStream>,
    subscribable_enum: Vec<proc_macro2::TokenStream>,
    app_parsers: HashSet<String>,
}

impl TrackedDataBuilder {
    pub(crate) fn new(subscribed_data: &SubscriptionConfig) -> Self {
        let mut ret = Self {
            update: vec![],
            struct_def: vec![],
            new: vec![],
            subscribable_enum: vec![],
            app_parsers: HashSet::new(),
        };
        ret.build(subscribed_data);
        ret
    }

    pub(crate) fn build(&mut self, subscribed_data: &SubscriptionConfig) {
        let mut datatypes = HashSet::new();
        for spec in &subscribed_data.subscriptions {
            let name = &spec.datatype_str; 
            let type_name = Ident::new(name, Span::call_site());
            let field_name = Ident::new(&name.to_lowercase(), Span::call_site());
            let needs_update = spec.datatype.needs_update; 
            let needs_parse = spec.datatype.needs_parse;
            if datatypes.contains(name) {
                continue;
            }
            datatypes.insert(name);
            if spec.datatype.from_session || 
               matches!(spec.datatype.level, Level::Packet) {
                // Data built directly from packet or session isn't tracked
                continue;
            }
            self.subscribable_enum.push(
                quote! { #type_name (#type_name), }
            );
            
            self.struct_def.push(
                quote! { 
                    #field_name : #type_name,
                }
            );
            self.new.push( 
                quote! { #field_name: #type_name::new(&five_tuple), }
            );
       
            if needs_update {
                // TODO will a subscription ever want to be able to know if *it* is matching 
                //              before the deliver phase? 
                self.update.push(
                    quote! { self.#field_name.update(pdu, session_id); }
                );
            }
            if needs_parse {
                self.app_parsers.insert(name.clone());
            }
        }
    }

    pub(crate) fn subscribable_wrapper(&mut self) -> proc_macro2::TokenStream {

        let mut conn_parsers = vec![];
        for datatype in &self.app_parsers {
            let type_ident = Ident::new(datatype, Span::call_site());

            conn_parsers.push(
                quote! {
                    ret.extend(#type_ident::conn_parsers());
                }
            );
        }

        quote! {
            pub struct SubscribedWrapper;

            impl Subscribable for SubscribedWrapper {
                type Tracked = TrackedWrapper;
                type SubscribedData = Subscribed;
                fn parsers() -> Vec<ConnParser> {
                    let mut ret = vec![];
                    #( #conn_parsers )*
                    ret
                }
            
                fn process_packet(
                    mbuf: Mbuf,
                    subscription: &Subscription<Self>,
                    conn_tracker: &mut ConnTracker<Self::Tracked>,
                    actions: Actions
                ) {
                    if actions.data.intersects(ActionData::PacketContinue) {
                        if let Ok(ctxt) = L4Context::new(&mbuf) {
                            conn_tracker.process(mbuf, ctxt, subscription);
                        }
                    }
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
        quote! {
            pub struct TrackedWrapper {
                five_tuple: FiveTuple,
                sessions: Vec<Session>,
                mbufs: Vec<Mbuf>,
                #( #def )*
            }

            impl Trackable for TrackedWrapper {
                type Subscribed = SubscribedWrapper;
    
                fn new(five_tuple: FiveTuple) -> Self {

                    Self {
                        five_tuple,
                        sessions: vec![],
                        mbufs: vec![],
                        #( #new )*
                    }
                }

                fn update(&mut self, 
                        pdu: &L4Pdu, 
                        session_id: Option<usize>, 
                        actions: &ActionData)
                {
                    #( #update )*
                }

                fn track_packet(&mut self, mbuf: Mbuf) {
                    self.mbufs.push(mbuf);
                }

                fn packets(&self) -> &Vec<Mbuf> {
                    &self.mbufs
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

                fn sessions(&self) -> &Vec<Session> {
                    &self.sessions
                }

                fn track_session(&mut self, session: Session) {
                    self.sessions.push(session);
                }
            }
        }
    }

}