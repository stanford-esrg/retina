use lazy_static::lazy_static;
use retina_core::filter::{DataType, Level};
use std::collections::HashMap;

use crate::*;

// To add a datatype, add it to the following map
// This is read by the filtergen crate.
lazy_static! {
    pub static ref DATATYPES: HashMap<&'static str, DataType> = {
        HashMap::from([
            (
                "Connection",
                DataType {
                    level: Level::Connection,
                    needs_parse: false,
                    needs_update: true,
                    needs_update_reassembled: false,
                    track_packets: false,
                    stream_protos: HttpTransaction::stream_protocols(),
                    as_str: "Connection",
                },
            ),
            (
                "HttpTransaction",
                DataType {
                    level: Level::Session,
                    needs_parse: true,
                    needs_update: false,
                    needs_update_reassembled: false,
                    track_packets: false,
                    stream_protos: HttpTransaction::stream_protocols(),
                    as_str: "HttpTransaction",
                },
            ),
            ("ZcFrame", {
                DataType {
                    level: Level::Packet,
                    needs_parse: false,
                    needs_update: false,
                    needs_update_reassembled: false,
                    track_packets: false,
                    stream_protos: vec![],
                    as_str: "ZcFrame",
                }
            }),
            ("Payload", {
                DataType {
                    level: Level::Packet,
                    needs_parse: false,
                    needs_update: false,
                    needs_update_reassembled: false,
                    track_packets: false,
                    stream_protos: vec![],
                    as_str: "Payload",
                }
            }),
            ("PacketList", {
                DataType {
                    level: Level::Connection,
                    needs_parse: false,
                    needs_update: false,
                    needs_update_reassembled: false,
                    track_packets: true,
                    stream_protos: vec![],
                    as_str: "PacketList",
                }
            }),
            ("SessionList", {
                DataType {
                    level: Level::Connection,
                    needs_parse: true,
                    needs_update: false,
                    needs_update_reassembled: false,
                    track_packets: false,
                    stream_protos: vec![],
                    as_str: "SessionList",
                }
            }),
            ("CoreId", {
                DataType {
                    level: Level::Static,
                    needs_parse: false,
                    needs_update: false,
                    needs_update_reassembled: false,
                    track_packets: false,
                    stream_protos: vec![],
                    as_str: "CoreId",
                }
            }),
            ("FiveTuple", {
                DataType {
                    level: Level::Static,
                    needs_parse: false,
                    needs_update: false,
                    needs_update_reassembled: false,
                    track_packets: false,
                    stream_protos: vec![],
                    as_str: "FiveTuple",
                }
            }),
        ])
    };
}

// Datatypes that are directly tracked by the framework
lazy_static! {
    pub static ref DIRECTLY_TRACKED: HashMap<&'static str, &'static str> = HashMap::from([
        ("PacketList", "packets"),
        ("SessionList", "sessions"),
        ("CoreId", "core_id")
    ]);
}

pub type PacketList = Vec<Mbuf>;
pub type SessionList = Vec<Session>;
