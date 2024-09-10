pub mod connection;
pub mod typedefs;
pub use connection::Connection;
pub mod http;
pub use http::HttpTransaction;
pub mod packet;
pub use packet::{Payload, ZcFrame};

pub use typedefs::{PacketList, SessionList};
pub use typedefs::{DATATYPES, SPECIAL_DATATYPES};

use retina_core::conntrack::conn_id::FiveTuple;
use retina_core::conntrack::pdu::L4Pdu;
use retina_core::protocols::stream::Session;
use retina_core::Mbuf;

pub trait Tracked {
    fn new(five_tuple: &FiveTuple) -> Self;
    fn update(&mut self, pdu: &L4Pdu, session_id: Option<usize>);
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
