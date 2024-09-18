pub mod connection;
pub mod typedefs;
pub use connection::Connection;
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

pub use typedefs::{PacketList, SessionList};
pub use typedefs::{DATATYPES, DIRECTLY_TRACKED};
pub use static_type::EtherTCI;

use retina_core::conntrack::pdu::L4Pdu;
use retina_core::protocols::stream::Session;
use retina_core::Mbuf;

pub trait Tracked {
    // Note `first_pkt` will also be delivered to `update`
    fn new(first_pkt: &L4Pdu) -> Self;
    fn update(&mut self, pdu: &L4Pdu, reassembled: bool);
    fn stream_protocols() -> Vec<&'static str>;
    fn session_matched(&mut self, session: &Session);
}

pub trait FromSession {
    fn stream_protocols() -> Vec<&'static str>;
    fn from_session(session: &Session) -> Option<&Self>;
}

pub trait FromMbuf {
    fn from_mbuf(mbuf: &Mbuf) -> Option<&Self>;
}

pub trait StaticData {
    fn new(first_pkt: &L4Pdu) -> Self;
}
