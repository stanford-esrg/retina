use quote::quote;
use std::collections::HashSet;
pub struct TlsHandshakeData;

impl TlsHandshakeData {

    #[inline]
    pub fn session_field() -> proc_macro2::TokenStream {
        quote! {
            tls: Rc<Option<Tls>>,
        }
    }

    #[inline]
    pub fn gen_new() -> proc_macro2::TokenStream {
        quote! {
            tls: Rc::new(None),
        }
    }

    #[inline]
    pub fn deliver_session_on_match(is_first: bool) -> proc_macro2::TokenStream {
        if !is_first {
            return quote! {
                else if let SessionData::Tls(tls) = session.data {
                    self.tls = Rc::new(Some(*tls));
                }
            };
        }
        quote! {
            if let SessionData::Tls(tls) = session.data {
                self.tls = Rc::new(Some(*tls));
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
        (quote! { pub tls: Rc<Option<Tls>>, },
         ["tls".to_string()].iter().cloned().collect(),
         quote! { tls: self.tls.clone(), } )
    }

    #[allow(dead_code)]
    pub fn condition() -> proc_macro2::TokenStream {
        // quote! { self.tls.is_some() }
        quote! {}
    }

}
