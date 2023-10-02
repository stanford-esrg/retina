use quote::quote;
use proc_macro2::Span;
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
        quote! { if !self.http.is_empty() { self.http.pop(); } }
    }

}

pub struct HttpSubscription;

impl HttpSubscription {

    pub fn delivered_field() -> (proc_macro2::TokenStream, HashSet<String>, proc_macro2::TokenStream) {
        ( quote! { pub http: Rc<Http>, },
          ["http".to_string()].iter().cloned().collect(),
          quote! { http: data.clone(), } )
    }

    pub fn condition() -> proc_macro2::TokenStream {
        quote! { 
            let Some(data) = self.http.last()
        }
    }
}

#[allow(dead_code)]
pub struct DefaultHttpSubscription;

#[allow(dead_code)]
impl DefaultHttpSubscription {
    pub fn struct_def() -> proc_macro2::TokenStream {
        quote! {
            #[derive(Debug)]
            pub struct HttpSubscription { 
                pub http: Rc<Http>,
                pub five_tuple: FiveTuple,
            }
        }
    }

    pub fn from_data(idx: i64) -> proc_macro2::TokenStream {
        // TODOTR iterate? 
        if idx < 0 {
            return quote! {};
        }
        let subscription_idx = syn::LitInt::new(&idx.to_string(), Span::call_site());
        quote! {
            if self.match_data.matched_term_by_idx(#subscription_idx) {
                if let Some(data) = self.http.last() {
                    subscription.invoke_idx(
                        Subscribed::Http(HttpSubscription {
                            http: data.clone(),
                            five_tuple: self.five_tuple
                        }
                    ),
                    #subscription_idx);
                }
            }
        }
    }

    pub fn enum_def() -> proc_macro2::TokenStream {
        quote! {
            Http(HttpSubscription),
        }
    }

    pub fn required_fields() -> HashSet<String> {
        ["five_tuple".to_string()].iter().cloned().collect()
    }
}