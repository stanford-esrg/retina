pub mod typedefs;
pub mod connection;
pub use connection::Connection;
pub mod http;
pub use http::HttpTransaction;

use retina_core::conntrack::pdu::L4Pdu;
use retina_core::protocols::stream::{ConnParser, Session};
use retina_core::conntrack::conn_id::FiveTuple;

pub enum Level {
    // Deliver per-packet
    Packet,
    // Deliver at termination
    Connection,
    // Deliver when session is parsed
    Session,
    // [TODO] need to think through
    Streaming,
}

pub struct DataType {
    pub level: Level, 
    // Datatype requires parsing app-level data
    pub needs_parse: bool, 
    // Datatype requires invoking `update` method
    pub needs_update: bool, 
    // [note] May want other things?
}

impl DataType {
    pub fn new(level: Level, needs_parse: bool, needs_update: bool) -> Self {
        Self {
            level,
            needs_parse,
            needs_update
        }
    }
}

pub trait Tracked {
    fn new(five_tuple: &FiveTuple) -> Self;
    fn update(&mut self, pdu: &L4Pdu, session_id: Option<usize>);
    fn conn_parsers() -> Vec<ConnParser>;
    fn session_matched(&mut self, session: &Session); 
}