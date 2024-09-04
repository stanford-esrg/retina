pub mod typedefs;
pub mod connection;
pub use connection::Connection;
pub mod http;
pub use http::HttpTransaction;
pub mod packet;
pub use packet::{ZcFrame, Payload};

pub use typedefs::DATATYPES;

use retina_core::conntrack::pdu::L4Pdu;
use retina_core::protocols::stream::Session;
use retina_core::conntrack::conn_id::FiveTuple;
use retina_core::Mbuf;

pub trait Tracked {
    fn new(five_tuple: &FiveTuple) -> Self;
    fn update(&mut self, pdu: &L4Pdu, session_id: Option<usize>);
    fn stream_protocols() -> Vec<&'static str>;
    fn session_matched(&mut self, session: &Session);
}

pub trait FromSession {
    fn stream_protocols() -> Vec<&'static str>;
    fn from_session<'a>(session: &'a Session) -> Option<&'a Self>;
}

pub trait FromMbuf {
    fn from_mbuf<'a>(mbuf: &'a Mbuf) -> Option<&'a Self>;
}