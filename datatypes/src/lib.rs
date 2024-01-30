use retina_core::conntrack::pdu::L4Pdu;
use retina_core::protocols::stream::{ConnParser, Session};
use retina_core::conntrack::conn_id::FiveTuple;

pub mod connection;
pub use connection::{Connection, TrackedConnection};

use std::collections::HashMap;

#[macro_use]
extern crate lazy_static;

// \todo generate in a better way?
// For the builder
lazy_static! {
    pub static ref CONN_PARSERS: HashMap<&'static str, Vec<ConnParser>> = 
        {
            HashMap::from([
                ( 
                    Connection::name(),
                    Connection::conn_parsers() 
                ),
            ])
        };
    
    pub static ref TRACKED_DATA_FIELDS: HashMap<&'static str, 
                    (String, String)> = 
        {
            HashMap::from([
                ( 
                    Connection::name(),
                    <Connection as SubscribedData>::T::named_data() 
                ),
            ])
        };
    
    pub static ref NEEDS_UPDATE: HashMap<&'static str, bool> = 
    {
        HashMap::from([
            ( 
                Connection::name(),
                <Connection as SubscribedData>::T::needs_update() 
            ),
        ])
    };

    pub static ref NEEDS_SESSION_MATCH: HashMap<&'static str, bool> = 
    {
        HashMap::from([
            ( 
                Connection::name(),
                <Connection as SubscribedData>::T::needs_session_match() 
            ),
        ])
    };

}

//// Build types that can be directly invoked ////
pub trait SubscribedData {
    type T: TrackedData;
    fn from_tracked(tracked: &Self::T, five_tuple: FiveTuple) -> Self;
    fn conn_parsers() -> Vec<ConnParser>;
    fn name() -> &'static str;
}

pub trait TrackedData {
    type S: SubscribedData;
    fn new() -> Self;
    // Format: field_name: Type
    // e.g., tracked_conn: TrackedConnection
    fn named_data() -> (String, String);

    fn needs_update() -> bool;
    fn update(&mut self, pdu: &L4Pdu, session_id: Option<usize>);
    
    fn needs_session_match() -> bool;
    fn session_matched(&mut self, session: &Session);
}


//// Build data for shared fields ////

// Build the fields required to track SubscribedData
#[derive(Debug)]
pub struct TrackedFieldBuilder {
    // Name of the field in the struct
    pub field: String,
    // Type of the field in the struct
    pub data_type: String,
    // Default value to use (or calculate) when `new` is invoked
    pub default_value: proc_macro2::TokenStream,
}

pub trait SubscribedDataBuilder {
    // Build SubscribedData from tracker.
    // Should directly access fields in the Trackable.
    fn from_tracked() -> proc_macro2::TokenStream;
    // Required fields for tracking data, each as a String
    // Should take the format (field, Type)
    fn tracked_fields() -> Vec<TrackedFieldBuilder>;
    // Update tracked data upon receipt of a frame
    fn update_tracked() -> proc_macro2::TokenStream;
    // Update tracked data upon receipt of a Session
    fn session_matched() -> proc_macro2::TokenStream;
    // Conn. parsers required
    fn conn_parsers() -> Vec<ConnParser>;
}

