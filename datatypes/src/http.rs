use retina_core::conntrack::conn_id::FiveTuple;
use retina_core::conntrack::pdu::L4Pdu;
use retina_core::protocols::stream::http::{parser::HttpParser, Http};
use retina_core::protocols::stream::{ConnParser, Session, SessionData};

use super::{SubscribedData, TrackedData};

// use serde::Serialize;
use std::rc::Rc;

#[derive(Debug)]
pub struct HttpTransaction {
    pub five_tuple: FiveTuple,
    pub data: Option<Rc<Http>>,
}

impl SubscribedData for HttpTransaction {
    type T = TrackedHttp;
    
    fn from_tracked(tracked: &Self::T, five_tuple: FiveTuple) -> Self {
        Self {
            five_tuple,
            data: match tracked.http.last() { // TODO there is automated way to do this
                Some(data) => Some(data.clone()),
                None => None,
            }
        }
    }

    fn conn_parsers() -> Vec<ConnParser> {
        vec![ConnParser::Http(HttpParser::default())]
    }

    fn name() -> &'static str {
        "HttpTransaction"
    }

}

pub struct TrackedHttp {
    http: Vec<Rc<Http>>,
}

impl TrackedData for TrackedHttp {
    type S = HttpTransaction;

    fn new() -> Self {
        Self {
            http: vec![]
        }
    }

    fn named_data() -> (String, String) {
        ( "tracked_http".into(), "TrackedHttp".into() )
    }

    fn needs_update() -> bool {
        false
    }

    fn update(&mut self, pdu: &L4Pdu, session_id: Option<usize>) {}

    fn needs_session_match() -> bool {
        true
    }

    fn session_matched(&mut self, session: &Session) {
        let session_data = session.data.clone();
        if let SessionData::Http(http) = session_data {
            self.http.push(Rc::new(*http)); // todo better data sharing
        }
    }
}
