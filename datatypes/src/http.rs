use retina_core::conntrack::conn_id::FiveTuple;
use retina_core::conntrack::pdu::L4Pdu;
use retina_core::protocols::stream::http::{parser::HttpParser, Http};
use retina_core::protocols::stream::{ConnParser, Session, SessionData};

use super::Tracked;

#[derive(Debug)]
pub struct HttpTransaction {
    pub five_tuple: FiveTuple,
    // \tmp change to lifetime per subscription [ideal] or Rc<RefCell
    pub data: Option<Box<Http>>
}

impl Tracked for HttpTransaction {

    fn new(five_tuple: &FiveTuple) -> Self {
        Self {
            five_tuple: five_tuple.clone(),
            data: None,
        }
    }

    fn conn_parsers() -> Vec<ConnParser> {
        vec![ConnParser::Http(HttpParser::default())]
    }

    fn update(&mut self, _pdu: &L4Pdu, _session_id: Option<usize>) {}

    fn session_matched(&mut self, session: &Session) {
        // \tmp Cloning until lifetimes or Rc<RefCell impl.
        let session_data = &session.data;
        if let SessionData::Http(http) = session_data {
            self.data = Some(http.clone());
        }
    }
}