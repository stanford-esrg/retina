pub mod typedefs;
pub mod connection;
pub use connection::Connection;
pub mod http;
pub use http::HttpTransaction;

pub use typedefs::DATATYPES;

use retina_core::conntrack::pdu::L4Pdu;
use retina_core::protocols::stream::{ConnParser, Session};
use retina_core::conntrack::conn_id::FiveTuple;


pub trait Tracked {
    fn new(five_tuple: &FiveTuple) -> Self;
    fn update(&mut self, pdu: &L4Pdu, session_id: Option<usize>);
    fn conn_parsers() -> Vec<ConnParser>;
    fn session_matched(&mut self, session: &Session); 
}