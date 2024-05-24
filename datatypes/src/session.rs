use retina_core::conntrack::conn_id::FiveTuple;
use retina_core::conntrack::pdu::L4Pdu;
use retina_core::protocols::stream::{ConnParser, Session};

use super::{SubscribedData, TrackedData};

// use serde::Serialize;
use std::rc::Rc;

#[derive(Debug)]
pub struct SubscribedSession {
    pub five_tuple: FiveTuple,
    pub data: Option<Rc<Session>>
}

impl SubscribedData for SubscribedSession {
    type T = TrackedSession;
    
    fn from_tracked(tracked: &Self::T, five_tuple: FiveTuple) -> Self {
        Self {
            five_tuple,
            data: match tracked.sessions.last() { 
                Some(data) => Some(data.clone()),
                None => None,
            }
        }
    }

    fn conn_parsers() -> Vec<ConnParser> {
        vec![
            retina_core::protocols::stream::ConnParser::Http(retina_core::protocols::stream::http::parser::HttpParser::default()),
            retina_core::protocols::stream::ConnParser::Dns(retina_core::protocols::stream::dns::parser::DnsParser::default()),
            retina_core::protocols::stream::ConnParser::Tls(retina_core::protocols::stream::tls::parser::TlsParser::default()),
        ]
    }

    fn name() -> &'static str {
        "SubscribedSession"
    }

}

pub struct TrackedSession {
    sessions: Vec<Rc<Session>>,
}

impl TrackedData for TrackedSession {
    type S = SubscribedSession;

    fn new() -> Self {
        Self {
            sessions: vec![]
        }
    }

    fn named_data() -> (String, String) {
        ( "tracked_session".into(), "TrackedSession".into() )
    }

    fn needs_update() -> bool {
        false
    }

    fn update(&mut self, pdu: &L4Pdu, session_id: Option<usize>) {}

    fn needs_session_match() -> bool {
        true
    }

    fn session_matched(&mut self, session: Rc<Session>) {
        self.sessions.push(session.clone());
    }
}
