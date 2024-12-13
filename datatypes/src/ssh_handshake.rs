//! A SSH handshake.
//! Subscribable alias for [`retina_core::protocols::stream::ssh::Ssh`]

use retina_core::protocols::stream::ssh::Ssh;
use retina_core::protocols::stream::{Session, SessionData};

use super::{FromSession, SessionList};

pub type SshHandshake = Box<Ssh>;

impl FromSession for SshHandshake {
    fn stream_protocols() -> Vec<&'static str> {
        vec!["ssh"]
    }

    fn from_session(session: &Session) -> Option<&Self> {
        if let SessionData::Ssh(ssh) = &session.data {
            return Some(ssh);
        }
        None
    }

    fn from_sessionlist(session_list: &SessionList) -> Option<&Self> {
        for session in session_list {
            if let SessionData::Ssh(ssh) = &session.data {
                return Some(ssh);
            }
        }
        None
    }
}
