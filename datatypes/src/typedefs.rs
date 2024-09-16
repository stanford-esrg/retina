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
                    false,
                    Connection::stream_protocols(),
                    "Connection",
                )
            }),
            ("HttpTransaction", {
                DataType::new(
                    Level::Session,
                    true,
                    false,
                    false,
                    HttpTransaction::stream_protocols(),
                    "HttpTransaction",
                )
            }),
            ("ZcFrame", {
                DataType::new(Level::Packet, false, false, false, vec![], "ZcFrame")
            }),
            ("Payload", {
                DataType::new(Level::Packet, false, false, false, vec![], "Payload")
            }),
            ("PacketList", {
                DataType::new(Level::Connection, false, false, true, vec![], "PacketList")
            }),
            ("SessionPacketList", {
                DataType::new(Level::Session, false, false, true, vec![], "PacketList")
            }),
            ("SessionList", {
                DataType::new(Level::Connection, true, false, false, vec![], "SessionList")
            }),
            ("CoreId", {
                DataType::new(Level::Static, false, false, false, vec![], "CoreId")
            }),
            ("FiveTuple", {
                DataType::new(Level::Static, false, false, false, vec![], "FiveTuple")
            }),
        ])
    };
}

// Datatypes that are directly tracked by the framework
lazy_static! {
    pub static ref DIRECTLY_TRACKED: HashMap<&'static str, &'static str> = HashMap::from([
        ("PacketList", "packets"),
        ("SessionList", "sessions"),
        ("SessionPacketList", "packets")
    ]);
}

pub type PacketList = Vec<Mbuf>;
pub type SessionPacketList = Vec<Mbuf>;
pub type SessionList = Vec<Session>;
