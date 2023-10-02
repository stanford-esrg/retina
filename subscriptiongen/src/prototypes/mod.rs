pub(crate) mod tls; 
pub(crate) mod http; 
pub(crate) mod utils;

pub use self::tls::{TlsHandshakeData, TlsSubscription};
pub use self::http::{HttpTransactionData, HttpSubscription};
pub use self::utils::FiveTupleData;

use std::collections::HashSet;

/*
// TODO define consts for fields, use Ident, match on str
pub const FIVE_TUPLE_FIELD: &str = "five_tuple";
pub const HTTP_FIELD: &str = "http";
pub const TLS_FIELD: &str = "tls";
 */

pub(crate) fn build_field(field_name: &str, field_value: Option<&str>) -> 
              (proc_macro2::TokenStream, HashSet<String>, proc_macro2::TokenStream) {
    if let Some(value) = field_value {
        assert!(value == "default");
    }
    return match field_name {
        "tls" => {  
            TlsSubscription::delivered_field()
        },
        "http" => {
            HttpSubscription::delivered_field()
        }, 
        "five_tuple" => {
            (FiveTupleData::delivered_field(), 
             ["five_tuple".to_string()].iter().cloned().collect(), 
             FiveTupleData::extract_field()
            )
        },
        _ => { panic!( "Unknown field" ) }
    };
}

pub(crate) fn build_condition(field_name: &str) -> Option<proc_macro2::TokenStream> {
    match field_name {
        "tls" => {  
            Some(TlsSubscription::condition())
        },
        "http" => {
            Some(HttpSubscription::condition())
        }, 
        _ => {
            None
        },
    }
}