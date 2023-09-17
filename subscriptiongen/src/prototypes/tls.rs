use quote::quote;
use proc_macro2::Span;

pub struct TlsHandshakeData;

impl TlsHandshakeData {

    #[inline]
    pub fn session_field() -> proc_macro2::TokenStream {
        quote! {
            tls: Option<Tls>,
        }
    }

    #[inline]
    pub fn gen_new() -> proc_macro2::TokenStream {
        quote! {
            tls: None,
        }
    }

    #[inline]
    pub fn deliver_session_on_match(is_first: bool, idx: i64) -> proc_macro2::TokenStream {
        // TODOTR figure out where to put #subscription -- should be in its 
        // own conceptual module
        let subscription = TlsSubscription::from_data(idx); 
        if !is_first {
            // TODOTR clean this up
            return quote! {
                else if let SessionData::Tls(tls) = session.data {
                    self.tls = Some(*tls); 
                    #subscription
                }
            };
        }
        quote! {
            if let SessionData::Tls(tls) = session.data {
                self.tls = Some(*tls); 
                #subscription
            }
        }
    }

    #[inline]
    pub fn parser() -> proc_macro2::TokenStream {
        quote! {
            ConnParser::Tls(TlsParser::default()),
        }
    }

}



pub struct TlsSubscription;

impl TlsSubscription {

    pub fn struct_def() -> proc_macro2::TokenStream {
        // TODOTR: should 5-tuple be in here? If so, add `fields` logic.
        quote! {
            pub struct TlsSubscription { 
                pub tls: Tls,
                pub five_tuple: FiveTuple,
            }
        }
    }

    pub fn from_data(idx: i64) -> proc_macro2::TokenStream {
        let subscription_idx = syn::LitInt::new(&idx.to_string(), Span::call_site());
        quote! {
            if let Some(_data) = &self.tls {
                subscription.invoke_idx(
                    SubscribableEnum::Tls(TlsSubscription {
                        tls: std::mem::take(&mut self.tls).unwrap(),
                        five_tuple: self.five_tuple,
                    }),
                    #subscription_idx
                );
            }
        }
    }

    pub fn enum_def() -> proc_macro2::TokenStream {
        quote! {
            Tls(TlsSubscription),
        }
    }
}