use retina_core::protocols::stream::http::Http;
use retina_core::protocols::stream::{Session, SessionData};

use super::FromSession;

pub type HttpTransaction = Box<Http>;

impl FromSession for HttpTransaction {

    fn stream_protocols() -> Vec<&'static str> {
        vec!["http"]
    }

    fn from_session(session: &Session) -> Option<&Self> {
        if let SessionData::Http(http) = &session.data {
            return Some(http);
        }
        None
    }
}