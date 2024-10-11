//! New datatypes are defined in this module.
//! Newly-defined datatypes must be added to the DATATYPES map in this module.

use lazy_static::lazy_static;
use retina_core::filter::{DataType, Level};
use std::collections::HashMap;

use crate::*;

// To add a datatype, add it to the following map
// This is read by the filtergen crate.
lazy_static! {
    pub static ref DATATYPES: HashMap<&'static str, DataType> = {
        HashMap::from([
            ("ConnRecord", DataType::new_default_connection("ConnRecord")),
            (
                "ConnDuration",
                DataType::new_default_connection("ConnDuration"),
            ),
            ("PktCount", DataType::new_default_connection("PktCount")),
            ("ByteCount", DataType::new_default_connection("ByteCount")),
            (
                "InterArrivals",
                DataType::new_default_connection("InterArrivals"),
            ),
            (
                "ConnHistory",
                DataType::new_default_connection("ConnHistory"),
            ),
            (
                "HttpTransaction",
                DataType::new_default_session(
                    "HttpTransaction",
                    HttpTransaction::stream_protocols(),
                ),
            ),
            (
                "DnsTransaction",
                DataType::new_default_session("DnsTransaction", DnsTransaction::stream_protocols()),
            ),
            (
                "TlsHandshake",
                DataType::new_default_session("TlsHandshake", TlsHandshake::stream_protocols()),
            ),
            (
                "QuicStream",
                DataType::new_default_session("QuicStream", QuicStream::stream_protocols()),
            ),
            ("ZcFrame", DataType::new_default_packet("ZcFrame")),
            ("Payload", DataType::new_default_packet("Payload")),
            ("PacketList", {
                DataType {
                    level: Level::Connection,
                    needs_parse: false,
                    track_sessions: false,
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
                    track_sessions: true,
                    needs_update: false,
                    needs_update_reassembled: false,
                    track_packets: false,
                    stream_protos: vec!["tls", "dns", "http", "quic"],
                    as_str: "SessionList",
                }
            }),
            ("CoreId", { DataType::new_default_static("CoreId") }),
            ("FiveTuple", { DataType::new_default_static("FiveTuple") }),
            ("EtherTCI", { DataType::new_default_static("EtherTCI") }),
            ("EthAddr", { DataType::new_default_static("EthAddr") }),
            ("FilterStr", { DataType::new_default_static("FilterStr") }),
        ])
    };
}

// Special cases: have specific conditions in generated code
// \Note ideally these would be implemented more cleanly
lazy_static! {
    // To avoid copying, the `Tracked` structure in the framework --
    // built at compile time -- will track certain generic, raw datatypes
    // if a subset of subscriptions require them.
    //
    // For example: buffering packets may be required as a pre-match action for a
    // packet-level datatype; it may also be required if one or more subscriptions request
    // a connection-level `PacketList`. Rather than maintaining these lists separately --
    // one for filtering and one for delivery -- the tracked packets are stored once.
    //
    // Core ID is a special case, as it cannot be derived from connection,
    // session, or packet data. It is simpler to define it as a directly tracked datatype.
    pub static ref DIRECTLY_TRACKED: HashMap<&'static str, &'static str> = HashMap::from([
        ("PacketList", "packets"),
        ("SessionList", "sessions"),
        ("CoreId", "core_id")
    ]);

    // Another special case -- datatype is the matched filter as a string literal.
    // \TODO ideally this would be a map to from_subscription function pointers
    pub static ref FILTER_STR: &'static str = "FilterStr";
}

pub type PacketList = Vec<Mbuf>;
pub type SessionList = Vec<Session>;
