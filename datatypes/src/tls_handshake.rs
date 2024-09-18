use retina_core::protocols::stream::tls::Tls;
use retina_core::protocols::stream::{Session, SessionData};

use super::FromSession;

pub type TlsHandshake = Box<Tls>;

impl FromSession for TlsHandshake {
    fn stream_protocols() -> Vec<&'static str> {
        vec!["tls"]
    }

    fn from_session(session: &Session) -> Option<&Self> {
        if let SessionData::Tls(tls) = &session.data {
            return Some(tls);
        }
        None
    }
}
