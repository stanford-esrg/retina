//! SSH parser.
//! 
//! Adapted from [the Rusticata SSH 
//! parser] (https://github.com/rusticata/ssh-parser/blob/master/src/ssh.rs)

use super::Ssh;
use crate::conntrack::pdu::L4Pdu;
use crate::protocols::stream::{
    ConnParsable, ParseResult, ParsingState, ProbeResult, Session, SessionData,
};

use ssh_parser::*;

#[derive(Debug)]
pub struct SshParser {
    sessions: Vec<Ssh>,
}

impl Default for SshParser {
    fn default() -> Self {
        SshParser {
            sessions: vec![Ssh::new()],
        }
    }
}

impl ConnParsable for SshParser {
    fn parse(&mut self, pdu: &L4Pdu) -> ParseResult {
        log::debug!("Updating parser ssh");
        let offset = pdu.offset();
        let length = pdu.length();
        if length == 0 {
            return ParseResult::Skipped;
        }

        if let Ok(data) = (pdu.mbuf_ref()).get_data_slice(offset, length) {
            if !self.sessions.is_empty() {
                return self.sessions[0].parse_packet(data, pdu.dir); // TODO
            }
            ParseResult::Skipped
        } else {
            log::warn("Malformed packet on parse");
            ParseResult::Skipped
        }
    }

    fn probe(&self, pdu: &L4Pdu) -> ProbeResult {
        let offset = pdu.offset();
        let length = pdu.length();

        // if payload is empty, unsure if SSH so keep sending packets
        if length == 0 {
            return ProbeResult::Unsure;
        }

        if let Ok(data) = (pdu.mbuf).get_data_slice(offset, length) {
            match (data[0], data[1], data[2], data[3]) {
                // bytes for the beginning of a SSH identification string: "SSH-"
                (0x53, 0x53, 0x48, 0x2d) => ProbeResult::Certain,
                _ => ProbeResult::NotForUs,
            }
        } else {
            log::warn!("Malformed packet");
            ProbeResult::Error
        }
    }
    
    fn remove_session(&mut self, _session_id: usize) -> Option<Session> {
        self.sessions.pop().map(|ssh| Session {
            data: SessionData::Ssh(Box::new(ssh)),
            id: 0,
        })
    }

    fn drain_sessions(&mut self) -> Vec<Session> {
        self.sessions
            .drain(..)
            .map(|ssh| Session {
                data: SessionData::Ssh(Box::new(ssh)),
                id: 0,
            })
            .collect()
    }

    fn session_parsed_state(&self) -> ParsingState {
        ParsingState::Stop
    }
}

impl SshParser {
    fn parse_packet(&mut self, data: &[u8], direction: bool) -> ParseResult {

    }
 }