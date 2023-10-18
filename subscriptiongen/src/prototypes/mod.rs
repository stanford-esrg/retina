pub(crate) mod tls; 
pub(crate) mod http; 
pub(crate) mod utils;
pub(crate) mod connection;

pub use self::tls::{TlsHandshakeData, TlsSubscription};
pub use self::http::{HttpTransactionData, HttpSubscription};
pub use self::connection::{ConnectionSubscription, ConnectionData};
pub use self::utils::FiveTupleData;

use std::collections::HashSet;

/*
// TODO define consts for fields, use Ident, match on str
pub const FIVE_TUPLE_FIELD: &str = "five_tuple";
pub const HTTP_FIELD: &str = "http";
pub const TLS_FIELD: &str = "tls";
 */

/// Return the struct field representing the user-requested data.
/// Example: if the user requested `tls` to be delivered with their struct, 
/// then this will produce the data needed to deliver `Tls` data to the user. 
/// Returned values: 
/// - struct field(s) for the delivered data,
/// - the name(s) of the field(s), as a string, and
/// - code to extract data from the tracker to deliver it to the user.
pub(crate) fn build_field(field_name: &str, field_value: Option<Vec<&str>>, 
                            is_connection: bool) -> 
              (proc_macro2::TokenStream, HashSet<String>, proc_macro2::TokenStream) {
    // TODO: filter out [more] sub-fields. 
    // No advantage now, since fields are parsed anyway by filter.
    if field_value.is_some() {
        println!("Warning: will ignore provided sub-fields");
    }
    return match field_name {
        "tls" => {  
            TlsSubscription::delivered_field()
        },
        "http" => {
            match is_connection {
                true => { HttpSubscription::conn_delivered_field() },
                false => { HttpSubscription::delivered_field() }
            }
        }, 
        "five_tuple" => {
            (FiveTupleData::delivered_field(), 
             ["five_tuple".to_string()].iter().cloned().collect(), 
             FiveTupleData::extract_field()
            )
        },
        "connection" => {
            ConnectionSubscription::delivered_field()
        }
        _ => { panic!( "Unknown field" ) }
    };
}

/// [Not currently used.]
/// Return code for a "check" that may need to happen to deliver data to the user.
/// For example: check if received session is Tls.
#[allow(dead_code)]
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