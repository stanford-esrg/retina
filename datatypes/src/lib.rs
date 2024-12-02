//!
//! Subscribable data types.
//!
//! A subscription is a request for a callback on a subset of network traffic specified by a filter.
//! Each callback function requires one or more *subscribable data types* as parameter(s), which it
//! immutably borrows.
//!
//! Each subscribable datatype must:
//!
//! - Be defined as a [retina_core::filter::DataType], with appropriate parameters and [retina_core::filter::Level].
//! - Implement one of the traits defined in this module (Tracked, FromSession, etc.)
//! - Be added to the [crate::typedefs::DATATYPES] map
//!
//!

pub mod conn_fts;
pub mod typedefs;
pub use conn_fts::*;
pub mod connection;
pub use connection::ConnRecord;
pub mod http_transaction;
pub use http_transaction::HttpTransaction;
pub mod dns_transaction;
pub use dns_transaction::DnsTransaction;
pub mod tls_handshake;
pub use tls_handshake::TlsHandshake;
pub mod quic_stream;
pub use quic_stream::QuicStream;
pub mod ssh_handshake;
pub use ssh_handshake::SshHandshake;
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
    /// Initialize internal data; called once per connection.
    /// Note `first_pkt` will also be delivered to `update`.
    fn new(first_pkt: &L4Pdu) -> Self;
    /// New packet in connection received (or reassembled, if reassembled=true)
    /// Note this may be invoked both pre- and post-reassembly; types
    /// should check `reassembled` to avoid double-counting.
    fn update(&mut self, pdu: &L4Pdu, reassembled: bool);
    /// The stream protocols (lower-case) required for this datatype.
    /// See `IMPLEMENTED_PROTOCOLS` in retina_core for list of supported protocols.
    fn stream_protocols() -> Vec<&'static str>;
    /// Clear internal data; called if connection no longer matches filter
    /// that requires the Tracked type.
    fn clear(&mut self);
}

/// Trait implemented by datatypes that are built from session data.
/// This is used when subscribing to specific parsed application-layer data.
pub trait FromSession {
    /// The stream protocols (lower-case) required for this datatype.
    /// See `IMPLEMENTED_PROTOCOLS` in retina_core for list of supported protocols.
    fn stream_protocols() -> Vec<&'static str>;
    /// Build Self from a parsed session, or return None if impossible.
    /// Invoked when the session is fully matched, parsed, and ready to
    /// be delivered to a callback.
    fn from_session(session: &Session) -> Option<&Self>;
    /// Build Self from a *list* of sessions, or return None if impossible.
    /// Invoked when the connection has terminated and a FromSession datatype
    /// must be delivered to a callback.
    fn from_sessionlist(sessionlist: &SessionList) -> Option<&Self>;
}

/// Trait implemented by datatypes that are built from a packet (Mbuf).
/// This is used when subscribing to packet-level data.
pub trait FromMbuf {
    fn from_mbuf(mbuf: &Mbuf) -> Option<&Self>;
}

/// Trait implemented by datatypes that are constant throughout
/// a connection and inferrable at first packet.
pub trait StaticData {
    fn new(first_pkt: &L4Pdu) -> Self;
}

/// Trait for a datatype that is built from a subscription specification.
/// [retina-filtergen](../filtergen) assumes that FilterStr is the only use-case for this.
#[doc(hidden)]
pub trait FromSubscription {
    /// Output the literal tokenstream (e.g., string literal) representing
    /// the constant value (e.g., matched filter string).
    fn from_subscription(spec: &SubscriptionSpec) -> proc_macro2::TokenStream;
}
