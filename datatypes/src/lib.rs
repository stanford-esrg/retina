pub mod typedefs;
pub mod conn_fts;
pub use conn_fts::ByteCounter;
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

pub trait Tracked {
    // Note `first_pkt` will also be delivered to `update`
    fn new(first_pkt: &L4Pdu) -> Self;
    // *this may be invoked 2x per packet* - 1x reassembled, 1x not
    fn update(&mut self, pdu: &L4Pdu, reassembled: bool);
    fn stream_protocols() -> Vec<&'static str>;
    fn session_matched(&mut self, session: &Session);
    fn clear(&mut self);
}

pub trait FromSession {
    fn stream_protocols() -> Vec<&'static str>;
    fn from_session(session: &Session) -> Option<&Self>;
    fn from_sessionlist(sessionlist: &SessionList) -> Option<&Self>;
}

pub trait FromMbuf {
    fn from_mbuf(mbuf: &Mbuf) -> Option<&Self>;
}

pub trait StaticData {
    fn new(first_pkt: &L4Pdu) -> Self;
}

/// Trait for a datatype that is built from a subscription specification.
/// The filtergen code and typedefs data structure assume that FilterStr is
/// the only use-case for this trait.
pub trait FromSubscription {
    fn from_subscription(spec: &SubscriptionSpec) -> proc_macro2::TokenStream;
}
