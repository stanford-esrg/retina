//! New datatypes are defined in this module.
//! Newly-defined datatypes must be added to the DATATYPES map in this module.

use lazy_static::lazy_static;
use proc_macro2::Span;
use quote::quote;
use retina_core::filter::{DataType, Level, SubscriptionSpec};
use std::collections::HashMap;

use crate::*;

lazy_static! {
    /// To add a datatype, add it to the DATATYPES map
    /// This is read by the filtergen crate to generate code
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
            (
                "SshHandshake",
                DataType::new_default_session("SshHandshake", SshHandshake::stream_protocols()),
            ),
            ("ZcFrame", DataType::new_default_packet("ZcFrame")),
            ("Payload", DataType::new_default_packet("Payload")),
            ("SessionList", {
                DataType {
                    level: Level::Connection,
                    needs_parse: true,
                    track_sessions: true,
                    needs_update: false,
                    needs_reassembly: false,
                    needs_packet_track: false,
                    stream_protos: vec!["tls", "dns", "http", "quic", "ssh"],
                    as_str: "SessionList",
                }
            }),
            ("BidirZcPktStream", { DataType::new_default_pktlist("BidirZcPktStream", false) }),
            ("OrigZcPktStream", { DataType::new_default_pktlist("OrigZcPktStream", false) }),
            ("RespZcPktStream", { DataType::new_default_pktlist("RespZcPktStream", false) }),
            ("OrigZcPktsReassembled", { DataType::new_default_pktlist("OrigZcPktsReassembled", true) }),
            ("RespZcPktsReassembled", { DataType::new_default_pktlist("RespZcPktsReassembled", true) }),
            ("BidirPktStream", { DataType::new_default_pktlist("BidirPktStream", false) }),
            ("OrigPktStream", { DataType::new_default_pktlist("OrigPktStream", false) }),
            ("RespPktStream", { DataType::new_default_pktlist("RespPktStream", false) }),
            ("OrigPktsReassembled", { DataType::new_default_pktlist("OrigPktsReassembled", true) }),
            ("RespPktsReassembled", { DataType::new_default_pktlist("RespPktsReassembled", true) }),
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
    /// To avoid copying, the `Tracked` structure in the framework --
    /// built at compile time -- will track certain generic, raw datatypes
    /// if a subset of subscriptions require them.
    ///
    /// For example: buffering packets may be required as a pre-match action for a
    /// packet-level datatype; it may also be required if one or more subscriptions request
    /// a connection-level `PacketList`. Rather than maintaining these lists separately --
    /// one for filtering and one for delivery -- the tracked packets are stored once.
    ///
    /// Core ID is a special case, as it cannot be derived from connection,
    /// session, or packet data. It is simpler to define it as a directly tracked datatype.
    ///
    /// The directly tracked datatypes are SessionList and CoreId
    pub static ref DIRECTLY_TRACKED: HashMap<&'static str, &'static str> = HashMap::from([
        ("SessionList", "sessions"),
        ("CoreId", "core_id")
    ]);

    /// See `FilterStr`
    #[doc(hidden)]
    pub static ref FILTER_STR: &'static str = "FilterStr";
}

/// A list of all sessions (zero-copy) parsed in the connection.
pub type SessionList = Vec<Session>;

/// The string literal representing a matched filter.
pub type FilterStr<'a> = &'a str;

impl FromSubscription for FilterStr<'_> {
    fn from_subscription(spec: &SubscriptionSpec) -> proc_macro2::TokenStream {
        let str = syn::LitStr::new(&spec.filter, Span::call_site());
        quote! { &#str }
    }
}
