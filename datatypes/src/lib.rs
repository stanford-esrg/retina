#![allow(clippy::needless_doctest_main)]
// #![warn(missing_docs)]
//!
//! Subscribable data types.
//!
//! A subscription is a request for a callback on a subset of network traffic specified by a filter.
//! Callback functions require one or more *subscribable data types* as parameter(s), which it
//! immutably borrows.
//!
//! Each subscribable datatype must be defined as a retina_core::DataType and must
//! implement one of the traits defined in this module.
//!

pub mod conn_fts;
pub mod typedefs;
pub use conn_fts::*;
pub mod connection;
pub use connection::ConnRecord;
pub mod http;
pub use http::HttpTransaction;
pub mod dns_transaction;
pub use dns_transaction::DnsTransaction;
pub mod tls_handshake;
pub use tls_handshake::TlsHandshake;
pub mod quic_stream;
pub use quic_stream::QuicStream;
pub mod packet;
pub use packet::{Payload, ZcFrame};
pub mod static_type;
pub use static_type::*;
pub use typedefs::*;

use retina_core::conntrack::pdu::L4Pdu;
use retina_core::filter::SubscriptionSpec;
use retina_core::protocols::stream::Session;
use retina_core::Mbuf;

/// Trait implemented by datatypes that require inline tracking.
/// This is typically required for subscribable types that require
/// calculating metrics throughout a connection, e.g. QoS metrics.
pub trait Tracked {
    // Note `first_pkt` will also be delivered to `update`
    fn new(first_pkt: &L4Pdu) -> Self;
    // *this may be invoked 2x per packet* - 1x reassembled, 1x not
    fn update(&mut self, pdu: &L4Pdu, reassembled: bool);
    fn stream_protocols() -> Vec<&'static str>;
    fn session_matched(&mut self, session: &Session);
    fn clear(&mut self);
}

/// Trait implemented by datatypes that are built from session data.
/// This is used when subscribing to specific parsed application-layer data.
pub trait FromSession {
    fn stream_protocols() -> Vec<&'static str>;
    fn from_session(session: &Session) -> Option<&Self>;
    fn from_sessionlist(sessionlist: &SessionList) -> Option<&Self>;
}

/// Trait implemented by datatypes that are built from a packet (Mbuf).
/// This is used when subscribing to packet-level data.
pub trait FromMbuf {
    fn from_mbuf(mbuf: &Mbuf) -> Option<&Self>;
}

/// Trait implemented by datatypes that are "Static", i.e.,
/// constant throughout a connection (or for all connections, e.g., CoreId)
/// and inferrable at first packet
pub trait StaticData {
    fn new(first_pkt: &L4Pdu) -> Self;
}

/// Trait for a datatype that is built from a subscription specification.
/// [retina-filtergen](../filtergen) assumes that FilterStr is the only use-case for this.
pub trait FromSubscription {
    fn from_subscription(spec: &SubscriptionSpec) -> proc_macro2::TokenStream;
}
