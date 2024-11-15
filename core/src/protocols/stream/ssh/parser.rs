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
                return self.sessions[0].process(data); // TODO
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

impl Ssh {
    /// Allocate a new SSH transaction instance.
    pub(crate) fn new() -> Ssh {
        Ssh {
            client_version_exchange: None,
            server_version_exchange: None,
            client_key_exchange: None,
            server_key_exchange: None,
            client_dh_key_exchange: None,
            server_dh_key_exchange: None,
            client_new_keys: None,
            server_new_keys: None,
            client_service_request: None,
            server_service_accept: None,
        }
    }

    pub(crate) fn parse_version_exchange(&mut self, data: &[u8]) {
        match ssh_parser::parse_ssh_identification(data) {
            Ok(pkt) => {
                let mut version_exchange = SshVersionExchange {
                    protoversion: pkt.proto,
                    softwareversion: pkt.software,
                    comments: pkt.comments,
                };
            }
            e => log::debug!("Could not parse SSH version exchange: {:?}", e),
        }
    }

    // pub(crate) fn parse_key_exchange(&mut self, content: &SshPacket) {
    //     match p {
    //         SshPacket::KeyExchange(pkt) => { 
    //             SshKeyExchange {
    //                 cookie: pkt.cookie.to_vec(),
    //                 kex_algs: pkt.kex_algs.to_vec(),
    //                 server_host_key_algs: pkt.server_host_key_algs.to_vec(),
    //                 encryption_algs_client_to_server: pkt.encr_algs_client_to_server.to_vec(),
    //                 encryption_algs_server_to_client: pkt.encr_algs_server_to_client.to_vec(),
    //                 mac_algs_client_to_server: pkt.mac_algs_client_to_server.to_vec(),
    //                 mac_algs_server_to_client: pkt.mac_algs_server_to_client.to_vec(),
    //                 compression_algs_client_to_server: pkt.comp_algs_client_to_server.to_vec(),
    //                 compression_algs_server_to_client: pkt.comp_algs_server_to_client.to_vec(),
    //                 languages_client_to_server: pkt.langs_client_to_server.to_vec(),
    //                 languages_server_to_client: pkt.langs_server_to_client.to_vec(),
    //                 first_kex_packet_follows: pkt.first_kex_packet_follows,
    //             }
    //         },
    //         _ => {
    //             panic!("Input must be a SSH Key Exchange packet.");
    //         }
    //     }
    // }

    // pub fn parse_dh_client_msg(p: SshPacket) {
    //     match p {
    //         SshPacket::DiffieHellmanInit(pkt) => { 
    //             SshDHClient {
    //                 e: pkt.e.to_vec(),
    //             }
    //         },
    //         _ => {
    //             panic!("Input must be a SSH Diffie-Hellman Client Message.");
    //         }
    //     }
    // }
    
    // pub fn parse_dh_server_response(p: SshPacket) {
    //     match p {
    //         SshPacket::DiffieHellmanReply(pkt) => { 
    //             SshDHServerResponse {
    //                 pubkey_and_certs: pkt.pubkey_and_cert.to_vec(),
    //                 f: pkt.f.to_vec(),
    //                 signature: pkt.signature.to_vec(),
    //             }
    //         },
    //         _ => {
    //             panic!("Input must be a SSH Diffie-Hellman Server Response.");
    //         }
    //     }
    // }

    // pub fn parse_service_req_or_response(p: SshPacket) {
    //     match p {
    //         SshPacket::ServiceRequest(pkt) => { 
    //             ServiceRequestAndResponse {
    //                 service_name: std::str::from_utf8(&pkt).expect("Invalid message.").to_string(),
    //             }
    //         },
    //         _ => {
    //             panic!("Input must be a Service Request or Service Response.");
    //         }
    //     }
    // }

    pub(crate) fn process(&mut self, data: &[u8]) -> ParseResult {
        let mut status = ParseResult::Continue(0);
        log::trace!("process ({} bytes)", data.len());
    }
}


impl SshParser {
}