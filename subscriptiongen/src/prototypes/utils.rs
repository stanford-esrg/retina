use quote::quote;

pub struct FiveTupleData {}

impl FiveTupleData {
    pub fn field() -> proc_macro2::TokenStream {
        quote! {
            five_tuple: FiveTuple,
        }
    }

    pub fn gen_new() -> proc_macro2::TokenStream {
        quote! {
            five_tuple: five_tuple,
        }
    }

    pub fn delivered_field() -> proc_macro2::TokenStream {
        quote! {
            pub five_tuple: FiveTuple,
        }
    }

    pub fn extract_field() -> proc_macro2::TokenStream {
        quote! {
            five_tuple: self.five_tuple,
        }
    }
}