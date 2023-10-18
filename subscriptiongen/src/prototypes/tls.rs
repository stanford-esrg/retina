use quote::quote;
use proc_macro2::Span;
use std::collections::HashSet;
pub struct TlsHandshakeData;

impl TlsHandshakeData {

    #[inline]
    pub fn session_field() -> proc_macro2::TokenStream {
        quote! {
            tls: Option<Rc<Tls>>,
        }
    }

    #[inline]
    pub fn gen_new() -> proc_macro2::TokenStream {
        quote! {
            tls: None,
        }
    }

    #[inline]
    pub fn deliver_session_on_match(is_first: bool) -> proc_macro2::TokenStream {
        if !is_first {
            return quote! {
                else if let SessionData::Tls(tls) = session.data {
                    self.tls = Some(Rc::new(*tls));
                }
            };
        }
        quote! {
            if let SessionData::Tls(tls) = session.data {
                self.tls = Some(Rc::new(*tls));
            }
        }
    }

    #[inline]
    pub fn parser() -> proc_macro2::TokenStream {
        quote! {
            ConnParser::Tls(TlsParser::default()),
        }
    }

    #[inline]
    pub fn drop() -> proc_macro2::TokenStream {
        quote! {}
        // quote! { self.tls = None; }
    }

}



pub struct TlsSubscription;

impl TlsSubscription {

    pub fn delivered_field() -> (proc_macro2::TokenStream, HashSet<String>, proc_macro2::TokenStream) {
        (quote! { pub tls: Rc<Tls>, },
         ["tls".to_string()].iter().cloned().collect(),
         quote! { tls: data.clone(), } )
    }

    pub fn condition() -> proc_macro2::TokenStream {
        quote! {  
            let Some(data) = &self.tls
        }
    }

}

#[allow(unused)]
pub struct DefaultTlsSubscription; 

#[allow(unused)]
impl DefaultTlsSubscription {
    pub fn struct_def() -> proc_macro2::TokenStream {
        quote! {
            #[derive(Debug)]
            pub struct TlsSubscription { 
                pub tls: Rc<Tls>,
                pub five_tuple: FiveTuple,
            }
        }
    }

    pub fn from_data(idx: i64) -> proc_macro2::TokenStream {
        if idx < 0 {
            return quote! {};
        }
        let subscription_idx = syn::LitInt::new(&idx.to_string(), Span::call_site());
        quote! {
            if self.match_data.matched_term_by_idx(#subscription_idx) {
                if let Some(data) = &self.tls {
                    subscription.invoke_idx(
                        Subscribed::Tls(TlsSubscription {
                            tls: data.clone(),
                            five_tuple: self.five_tuple,
                        }),
                        #subscription_idx
                    );
                }
            }
        }
    }

    pub fn required_fields() -> HashSet<String> {
        ["five_tuple".to_string()].iter().cloned().collect()
    }
}