use lazy_static::lazy_static;
use retina_core::filter::{DataType, Level};
use std::collections::HashMap;

use crate::*;

// To add a datatype, add it to the following map
// This is read by the filtergen crate.
lazy_static! {
    pub static ref DATATYPES: HashMap<&'static str, DataType> = {
        HashMap::from([
            ("Connection", {
                DataType::new(
                    Level::Connection,
                    false,
                    true,
                    Connection::stream_protocols(),
                    "Connection",
                )
            }),
            ("HttpTransaction", {
                DataType::new(
                    Level::Session,
                    true,
                    false,
                    HttpTransaction::stream_protocols(),
                    "HttpTransaction",
                )
            }),
            ("ZcFrame", {
                DataType::new(Level::Packet, false, false, vec![], "ZcFrame")
            }),
            ("Payload", {
                DataType::new(Level::Packet, false, false, vec![], "Payload")
            }),
            ("PacketList", {
                DataType::new(Level::Packet, false, false, vec![], "PacketList")
            }),
            ("SessionList", {
                DataType::new(Level::Session, false, false, vec![], "SessionList")
            }),
        ])
    };
}

// TODO RETHINK ORGANIZATION??
lazy_static! {
    pub static ref SPECIAL_DATATYPES: HashMap<&'static str, &'static str> =
        HashMap::from([("PacketList", "packets"), ("SessionList", "sessions"),]);
}

pub type PacketList = Vec<Mbuf>;
pub type SessionList = Vec<Session>;
