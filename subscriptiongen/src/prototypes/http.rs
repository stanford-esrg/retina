use quote::quote;
use proc_macro2::Span;

pub struct HttpTransactionData {}

impl HttpTransactionData {

    #[inline]
    pub fn session_field() -> proc_macro2::TokenStream {
        quote! {
            http: Vec<Http>,
        }
    }

    #[inline]
    pub fn gen_new() -> proc_macro2::TokenStream {
        quote! {
            http: Vec::new(),
        }
    }

    #[inline]
    pub fn deliver_session_on_match(is_first: bool, idx: i64) -> proc_macro2::TokenStream {
        let subscription_idx = syn::LitInt::new(&idx.to_string(), Span::call_site());
        if !is_first {
            return quote! {
                else if let SessionData::Http(http) = session.data {
                    if self.match_data.matched_term_by_idx(#subscription_idx) {
                        self.http.push(*http); 
                    }
                }
            };
        }
        quote! {
            if let SessionData::Http(http) = session.data {
                if self.match_data.matched_term_by_idx(#subscription_idx) {
                    self.http.push(*http); 
                }
            }
        }
    }

    #[inline]
    pub fn parser() -> proc_macro2::TokenStream {
        quote! {
            ConnParser::Http(HttpParser::default()),
        }
    }

}

pub struct HttpSubscription;

impl HttpSubscription {

    pub fn struct_def() -> proc_macro2::TokenStream {
        quote! {
            pub struct HttpSubscription { 
                pub http: Http,
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
                if let Some(data) = self.http.pop() {
                    subscription.invoke_idx(
                        SubscribableEnum::Http(HttpSubscription {
                            http: data,
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
}