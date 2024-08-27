use retina_core::protocols::stream::http::{parser::HttpParser, Http};
use retina_core::protocols::stream::{ConnParser, Session, SessionData};

use super::FromSession;

pub type HttpTransaction = Box<Http>;

impl FromSession for HttpTransaction {

    fn conn_parsers() -> Vec<ConnParser> {
        vec![ConnParser::Http(HttpParser::default())]
    }

    fn from_session<'a>(session: &'a Session) -> Option<&'a Self> {
        if let SessionData::Http(http) = &session.data {
            return Some(http);
        }
        None
    }
}