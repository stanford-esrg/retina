use retina_core::filter::datatypes::{Level, DataType};
use lazy_static::lazy_static;
use std::collections::HashMap;

use crate::*;

// To add a datatype, add it to the following map
// This is read by the filtergen crate.
lazy_static! {
    pub static ref DATATYPES: HashMap<&'static str, DataType> =
    {
        HashMap::from([
            (
                "Connection",
                { DataType::new(Level::Connection, false, true, Connection::stream_protocols()) }
            ),
            (
                "HttpTransaction",
                { DataType::new(Level::Session, true, false, HttpTransaction::stream_protocols()) }
            ),
            (
                "ZcFrame",
                { DataType::new(Level::Packet, false, false, vec![]) }
            ),
            (
                "Payload",
                { DataType::new(Level::Packet, false, false, vec![]) }
            ),
        ])
    };
}