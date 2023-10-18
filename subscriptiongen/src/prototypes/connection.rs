use quote::quote;
use std::collections::HashSet;
use proc_macro2::Span;

/// At this point, connections are not customizable.
pub struct ConnectionSubscription;

impl ConnectionSubscription {

    pub(crate) fn delivered_field() -> (proc_macro2::TokenStream, 
                                 HashSet<String>, 
                                 proc_macro2::TokenStream) {
        (quote! { pub connection: Rc<Connection>, },
         ["connection".to_string()].iter().cloned().collect(),
         quote! { connection: connection.clone(), } )
    }
}

pub struct ConnectionData;

impl ConnectionData {
    pub fn gen_new() -> proc_macro2::TokenStream {
        quote! {
            connection: TrackedConnection::new(five_tuple, FilterResultData::new()),
        }
    }

    pub fn tracked_field() -> proc_macro2::TokenStream {
        quote! { connection: TrackedConnection, }
    }

    pub fn gen_update(bitmask: usize) -> proc_macro2::TokenStream {
        let bitmask_lit = syn::LitInt::new(&bitmask.to_string(), Span::call_site());
        quote! { 
            if self.match_data.matching_by_bitmask(#bitmask_lit) {
                self.connection.update_data(pdu) 
            }
        }
    }

    pub fn get_conn() -> proc_macro2::TokenStream {
        quote! { let connection = Rc::new( self.connection.to_connection() ); }
    }
}