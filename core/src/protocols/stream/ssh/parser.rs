//! SSH parser.
//! 
//! Adapted from [the Rusticata SSH 
//! parser] (https://github.com/rusticata/ssh-parser/blob/master/src/ssh.rs)

use super::transaction::SshServiceRequest;
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

    pub(crate) fn parse_version_exchange(&mut self, data: &[u8], dir: bool) {
        let ssh_identifier = b"SSH-";
        if let Some(contains_ssh_identifier) = data.windows(ssh_identifier.len()).position(|window| window == ssh_identifier).map(|p| &data[p..]) {
            match ssh_parser::parse_ssh_identification(contains_ssh_identifier) {
                Ok((_, (_, ssh_id_string))) => {
                    let version_exchange = SshVersionExchange {
                        protoversion: String::from_utf8(ssh_id_string.proto.to_vec()).expect("Invalid message.").clone(),
                        softwareversion: String::from_utf8(ssh_id_string.software.to_vec()).expect("Invalid message.").clone(),
                        comments: if ssh_id_string.comments.map(|b| !b.is_empty()).unwrap_or(false) {
                            let comments_vec = ssh_id_string.comments.map(|b| b.to_vec()).unwrap_or_else(|| Vec::new());
                            Some(String::from_utf8(comments_vec).expect("Invalid message.").clone())
                        } else {
                            None
                        }
                    };

                    if dir {
                        self.client_version_exchange = version_exchange;
                    } else {
                        self.server_version_exchange = version_exchange;
                    }
                }
                e => println!("Could not parse SSH version exchange: {:?}", e),
            }
        }
    }

    fn bytes_to_string_vec(&mut self, data: &[u8]) -> Vec<String> {
        data.split(|&b| b == b',').map(|chunk| String::from_utf8(chunk.to_vec()).unwrap()).collect()
    }

    pub(crate) fn parse_key_exchange(&mut self, data: &[u8], dir: bool) {
        match ssh_parser::parse_ssh_packet(data) {
            Ok((_, (pkt, _))) => {
                match pkt {
                    SshPacket::KeyExchange(pkt) => {
                        let key_exchange = SshKeyExchange {
                            cookie: pkt.cookie.to_vec(),
                            kex_algs: bytes_to_string_vec(pkt.kex_algs),
                            server_host_key_algs: bytes_to_string_vec(pkt.server_host_key_algs),
                            encryption_algs_client_to_server: bytes_to_string_vec(pkt.encr_algs_client_to_server),
                            encryption_algs_server_to_client: bytes_to_string_vec(pkt.encr_algs_server_to_client),
                            mac_algs_client_to_server: bytes_to_string_vec(pkt.mac_algs_client_to_server),
                            mac_algs_server_to_client: bytes_to_string_vec(pkt.mac_algs_server_to_client),
                            compression_algs_client_to_server: bytes_to_string_vec(pkt.comp_algs_client_to_server),
                            compression_algs_server_to_client: bytes_to_string_vec(pkt.comp_algs_server_to_client),
                            languages_client_to_server: if !pkt.langs_client_to_server.is_empty() { Some(bytes_to_string_vec(pkt.langs_client_to_server)) } else { None },
                            languages_server_to_client: if !pkt.langs_server_to_client.is_empty() { Some(bytes_to_string_vec(pkt.langs_server_to_client)) } else { None },
                            first_kex_packet_follows: pkt.first_kex_packet_follows,
                        };

                        if dir {
                            self.client_key_exchange = key_exchange;
                        } else {
                            self.server_key_exchange = key_exchange;
                        }
                    }
                e => println!("Could not parse SSH key exchange 2: {:?}", e),
                }
            }
            e => println!("Could not parse SSH key exchange 1: {:?}", e),
        }
    }
    
    pub(crate) fn parse_dh_client_init(&mut self, data: &[u8]) {
        match ssh_parser::parse_ssh_packet(data) {
            Ok((_, (pkt, _))) => {
                match pkt {
                    SshPacket::DiffieHellmanInit(pkt) => {
                        let dh_init = SshDhInit {
                            e: pkt.e.to_vec(),
                        };

                        self.client_dh_key_exchange = dh_init;
                        
                    }
                e => println!("Could not parse DH init 2: {:?}", e),
                }
            }
            e => println!("Could not parse DH init 1: {:?}", e),
        }
    }

    pub(crate) fn parse_dh_server_response(&mut self, data: &[u8]) {
        match ssh_parser::parse_ssh_packet(data) {
            Ok((_, (pkt, _))) => {
                match pkt {
                    SshPacket::DiffieHellmanReply(pkt) => {
                        let dh_response = SshDhResponse {
                            pubkey_and_certs: pkt.pubkey_and_cert.to_vec(),
                            f: pkt.f.to_vec(),
                            signature: pkt.signature.to_vec(),
                        };

                        self.server_dh_key_exchange = dh_response;
                    }
                e => println!("Could not parse DH server response 2: {:?}", e),
                }
            }
            e => println!("Could not parse DH server response 1: {:?}", e),
        }
    }

    pub(crate) fn parse_new_keys(&mut self, data: &[u8]) {
        match ssh_parser::parse_ssh_packet(data) {
            Ok((_, (pkt, _))) => {
                match pkt {
                    SshPacket::NewKeys => {
                        self.server_dh_key_exchange = SshPacket::NewKeys;
                    }
                e => println!("Could not parse new keys 2: {:?}", e),
                }
            }
            e => println!("Could not parse new keys 1: {:?}", e),
        }
    }

    pub(crate) fn parse_service_request(&mut self, data: &[u8]) {
        match ssh_parser::parse_ssh_packet(data) {
            Ok((_, (pkt, _))) => {
                match pkt {
                        SshPacket::ServiceRequest(pkt) => {
                            let service_response = SshServiceRequest {
                                service_name: String::from_utf8(pkt.to_vec()).expect("Invalid message.").clone(),
                            };

                            self.client_service_request = service_response;
                        }
                e => println!("Could not parse service request 2: {:?}", e),
                }
            }
            e => println!("Could not parse service request 1: {:?}", e),
        }
    }

    pub(crate) fn parse_service_accept(&mut self, data: &[u8]) {
        match ssh_parser::parse_ssh_packet(data) {
            Ok((_, (pkt, _))) => {
                match pkt {
                        SshPacket::ServiceAccept(pkt) => {
                            let service_accept = SshServiceAccept {
                                service_name: String::from_utf8(pkt.to_vec()).expect("Invalid message.").clone(),
                            };

                            self.server_service_accept = service_accept;
                        }
                e => println!("Could not parse service accept 2: {:?}", e),
                }
            }
            e => println!("Could not parse service accept 1: {:?}", e),
        }
    }

    pub(crate) fn process(&mut self, data: &[u8]) -> ParseResult {
        let mut status = ParseResult::Continue(0);
        log::trace!("process ({} bytes)", data.len());
    }
}


impl SshParser {
}