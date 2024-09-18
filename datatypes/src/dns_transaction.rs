use retina_core::protocols::stream::dns::Dns;
use retina_core::protocols::stream::{Session, SessionData};

use super::FromSession;

pub type DnsTransaction = Box<Dns>;

impl FromSession for DnsTransaction {
    fn stream_protocols() -> Vec<&'static str> {
        vec!["dns"]
    }

    fn from_session(session: &Session) -> Option<&Self> {
        if let SessionData::Dns(dns) = &session.data {
            return Some(dns);
        }
        None
    }
}
