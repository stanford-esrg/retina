pub(crate) mod parser; // TODO: privatize this, remove dependencies on ssh_parser

use self::parser::*;
use super::ConnParsable;
use crate::conntrack::pdu::L4Pdu;
use crate::protocols::stream::{ParseResult, ProbeResult};

use rusticata::*;
use std::collections::VecDeque;
use std::fmt;

/// SSH handshake parser
// #[derive(Debug)]
pub struct Ssh {
    pub parser: VecDeque<SshParser>,
    pub(crate) last_update_id: Option<usize>,
}

#[allow(dead_code)]
impl SshParser {
    // TODO: more fields...
    pub fn client_protocol(&self) -> Vec<u8> {
        self.client_proto.clone()
    }

    pub fn server_protocol(&self) -> Vec<u8> {
        self.server_proto.clone()
    }

    pub fn client_software(&self) -> Vec<u8> {
        self.client_software.clone()
    }

    pub fn server_software(&self) -> Vec<u8> {
        self.server_software.clone()
    }
}

impl ConnParsable for Ssh {
    fn parse(&mut self, segment: &L4Pdu) -> ParseResult {
        log::debug!("Updating parser ssh");
        let offset = segment.offset();
        let length = segment.length();
        if let Ok(data) = (segment.mbuf_ref()).get_data_slice(offset, length) {
            let direction = if segment.dir {
                Direction::ToServer
            } else {
                Direction::ToClient
            };
            // log::debug!("status: {:#?}", status);
            // Only one session per conn
            self.last_update_id = Some(0);
            match self.parser[0].parse_l4(data, direction) {
                rusticata::ParseResult::Ok => ParseResult::Ok,
                rusticata::ParseResult::Stop => ParseResult::Done,
                // ProtocolChanged, Error, or Fatal
                _ => ParseResult::Error,
            }
        } else {
            log::warn!("Malformed packet");
            ParseResult::Error
        }
    }

    fn probe(&self, segment: &L4Pdu) -> ProbeResult {
        if segment.length() <= 4 {
            return ProbeResult::Unsure;
        }
        let offset = segment.offset();
        let length = segment.length();
        if let Ok(data) = (segment.mbuf_ref()).get_data_slice(offset, length) {
            if &data[..4] == b"SSH-" {
                ProbeResult::Certain
            } else {
                ProbeResult::NotForUs
            }
        } else {
            log::warn!("Malformed packet");
            ProbeResult::Error
        }
    }
}

impl Default for Ssh {
    fn default() -> Self {
        let mut parser = VecDeque::new();
        parser.push_back(SshParser::default());
        Ssh {
            parser,
            last_update_id: None,
        }
    }
}

impl fmt::Debug for Ssh {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ssh")
            .field("parser", &"SshParser".to_string())
            .finish()
    }
}
