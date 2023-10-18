use quote::quote;
use std::collections::HashSet;

pub struct HttpTransactionData {}

impl HttpTransactionData {

    #[inline]
    pub fn session_field() -> proc_macro2::TokenStream {
        quote! {
            http: Vec<Rc<Http>>,
        }
    }

    #[inline]
    pub fn gen_new() -> proc_macro2::TokenStream {
        quote! {
            http: Vec::new(),
        }
    }

    #[inline]
    pub fn deliver_session_on_match(is_first: bool) -> proc_macro2::TokenStream {
        if !is_first {
            return quote! {
                else if let SessionData::Http(http) = session.data {
                    self.http.push(Rc::new(*http)); 
                }
            };
        }
        quote! {
            if let SessionData::Http(http) = session.data {
                self.http.push(Rc::new(*http));
            }
        }
    }

    #[inline]
    pub fn parser() -> proc_macro2::TokenStream {
        quote! {
            ConnParser::Http(HttpParser::default()),
        }
    }

    pub fn drop() -> proc_macro2::TokenStream {
        quote! {}
        // quote! { if !self.http.is_empty() { self.http.pop(); } }
    }

}

pub struct HttpSubscription;

impl HttpSubscription {

    pub fn delivered_field() -> (proc_macro2::TokenStream, HashSet<String>, proc_macro2::TokenStream) {
        ( quote! { pub http: Option<Rc<Http>>, },
          ["http".to_string()].iter().cloned().collect(),
          quote! { http: match self.http.last() { 
                               Some(data) => { Some(data.clone()) },
                               None => { None }
                         },
                }
        )
    }

    #[allow(dead_code)]
    pub fn condition() -> proc_macro2::TokenStream {
        quote! { 
            let Some(data) = self.http.last()
        }
    }

    pub fn conn_delivered_field() -> (proc_macro2::TokenStream, HashSet<String>, proc_macro2::TokenStream) {
        (quote! { pub http: Vec<Rc<Http>>, },
        ["http".to_string()].iter().cloned().collect(),
        quote! { http: self.http.clone(), })
    }

}
