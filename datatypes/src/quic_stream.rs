//! A Quic stream.
//! Subscribable alias for [`retina_core::protocols::stream::quic::QuicConn`]

use retina_core::protocols::stream::quic::QuicConn;
use retina_core::protocols::stream::{Session, SessionData};

use super::{FromSession, SessionList};

pub type QuicStream = Box<QuicConn>;

impl FromSession for QuicStream {
    fn stream_protocols() -> Vec<&'static str> {
        vec!["quic"]
    }

    fn from_session(session: &Session) -> Option<&Self> {
        if let SessionData::Quic(quic) = &session.data {
            return Some(quic);
        }
        None
    }

    fn from_sessionlist(session_list: &SessionList) -> Option<&Self> {
        for session in session_list {
            if let SessionData::Quic(quic) = &session.data {
                return Some(quic);
            }
        }
        None
    }
}
