// borrowed from https://github.com/rusticata/rusticata/blob/master/src/ssh.rs
use nom::{Err, HexDisplay};
use rusticata::*;
use ssh_parser::{parse_ssh_identification, parse_ssh_packet, SshPacket};

#[derive(Debug, PartialEq)]
enum SshConnectionState {
    Start,
    CIdent,
    SIdent,
    CKexInit,
    SKexInit,
    CKexDh,
    SKexDh,
    Established,
    Error,
}

pub struct SshParser {
    // session ID (only for frame subscription)
    pub(crate) id: usize,
    state: SshConnectionState,
    /// data buffer client
    buffer_clt: Vec<u8>,
    // data buffer server
    buffer_srv: Vec<u8>,
    /// ssh protocol version
    pub(crate) client_proto: Vec<u8>,
    pub(crate) server_proto: Vec<u8>,
    /// ssh software
    pub(crate) client_software: Vec<u8>,
    pub(crate) server_software: Vec<u8>,
    pub(crate) client_ssh_alg: SshKeyExchange,
    pub(crate) server_ssh_alg: SshKeyExchange,
    pub(crate) client_dh_key_e: Vec<u8>,
    pub(crate) server_dh_reply: SshDhReply,
}

impl SshParser {
    pub fn default() -> Self {
        SshParser {
            id: 0,
            state: SshConnectionState::Start,
            buffer_clt: Vec::new(),
            buffer_srv: Vec::new(),
            client_proto: Vec::new(),
            client_software: Vec::new(),
            server_proto: Vec::new(),
            server_software: Vec::new(),
            client_ssh_alg: SshKeyExchange::default(),
            server_ssh_alg: SshKeyExchange::default(),
            client_dh_key_e: Vec::new(),
            server_dh_reply: SshDhReply::default(),
        }
    }

    fn parse_field(&mut self, pkt: &(SshPacket, &[u8]), direction: Direction) {
        #[allow(clippy::single_match)]
        match pkt.0 {
            SshPacket::KeyExchange(ref kex) => {
                let mut sender = if direction == Direction::ToServer {
                    &mut self.client_ssh_alg
                } else {
                    &mut self.server_ssh_alg
                };
                sender.cookie = kex.cookie.to_vec();
                sender.kex_algs = kex.kex_algs.to_vec();
                sender.server_host_key_algs = kex.server_host_key_algs.to_vec();
                sender.encr_algs_client_to_server = kex.encr_algs_client_to_server.to_vec();
                sender.encr_algs_server_to_client = kex.encr_algs_server_to_client.to_vec();
                sender.mac_algs_client_to_server = kex.mac_algs_client_to_server.to_vec();
                sender.mac_algs_server_to_client = kex.mac_algs_server_to_client.to_vec();
                sender.comp_algs_client_to_server = kex.comp_algs_client_to_server.to_vec();
                sender.comp_algs_server_to_client = kex.comp_algs_server_to_client.to_vec();
                sender.langs_client_to_server = kex.langs_client_to_server.to_vec();
                sender.langs_server_to_client = kex.langs_server_to_client.to_vec();
                sender.first_kex_packet_follows = kex.first_kex_packet_follows;
            }
            SshPacket::DiffieHellmanInit(ref dhi) => {
                self.client_dh_key_e = dhi.e.to_vec();
            }
            SshPacket::DiffieHellmanReply(ref dhr) => {
                self.server_dh_reply.pubkey_and_cert = dhr.pubkey_and_cert.to_vec();
                self.server_dh_reply.f = dhr.f.to_vec();
                self.server_dh_reply.signature = dhr.signature.to_vec();
            }
            _ => (),
        }
    }

    fn parse_ident(&mut self, i: &[u8], direction: Direction) -> ParseResult {
        match parse_ssh_identification(i) {
            Ok((rem, (ref crap, ref res))) => {
                // In version 2.0, the SSH server is allowed to send an arbitrary number of
                // UTF-8 lines before the final identification line containing the server
                // version.
                if !crap.is_empty() {
                    log::info!("Extra lines before SSH version:");
                    for line in crap.iter() {
                        log::info!("{}", line.to_hex(16));
                    }
                }
                if !rem.is_empty() {
                    log::warn!("Extra bytes after SSH ident data");
                }
                log::debug!("parse_ssh_identification: {:?}", res);
                self.state = match self.state {
                    SshConnectionState::Start => SshConnectionState::CIdent,
                    SshConnectionState::CIdent => SshConnectionState::SIdent,
                    _ => {
                        return ParseResult::Error;
                    }
                };
                if direction == Direction::ToServer {
                    self.client_proto = res.proto.to_vec();
                    self.client_software = res.software.to_vec();
                } else {
                    self.server_proto = res.proto.to_vec();
                    self.server_software = res.software.to_vec();
                }
                // log::info!("protocol\n{}", res.proto.to_hex(16));
                // log::info!("software\n{}", res.software.to_hex(16));
            }
            e => {
                log::warn!("parse_ssh_identification: {:?}", e);
                self.state = SshConnectionState::Error;
            }
        };
        ParseResult::Ok
    }

    fn parse_packet(&mut self, i: &[u8], direction: Direction) -> ParseResult {
        log::debug!("parse_ssh_packet direction: {:?}", direction);
        log::debug!("\tbuffer_clt size: {}", self.buffer_clt.len());
        log::debug!("\tbuffer_srv size: {}", self.buffer_srv.len());
        if self.state == SshConnectionState::Established {
            // stop following session when encrypted
            // return ParseResult::Ok;
            return ParseResult::Stop;
        }
        let mut v: Vec<u8>;
        // Check if a record is being defragmented
        let self_buffer = if direction == Direction::ToServer {
            &mut self.buffer_srv
        } else {
            &mut self.buffer_clt
        };
        let buf = match self_buffer.len() {
            0 => i,
            _ => {
                v = self_buffer.split_off(0);
                v.extend_from_slice(i);
                v.as_slice()
            }
        };
        // log::info!("parsing:\n{}", buf.to_hex(16));
        // println!("all states: {:#?}", self.state);
        match parse_ssh_packet(buf) {
            Ok((rem, res)) => {
                // put back remaining data
                self_buffer.extend_from_slice(rem);
                self.parse_field(&res, direction);

                self.state = match self.state {
                    SshConnectionState::SIdent => SshConnectionState::CKexInit,
                    SshConnectionState::CKexInit => SshConnectionState::SKexInit,
                    SshConnectionState::SKexInit => SshConnectionState::CKexDh,
                    SshConnectionState::CKexDh => SshConnectionState::SKexDh,
                    SshConnectionState::SKexDh => SshConnectionState::Established,
                    _ => {
                        return ParseResult::Error;
                    }
                };
                println!("all states: {:#?}", self.state);
            }
            Err(Err::Incomplete(_e)) => {
                log::debug!("Defragmentation required (SSH packet): {:?}", _e);
                self_buffer.extend_from_slice(buf);
            }
            e => {
                log::warn!("state: {:#?}, parse_ssh_packet: {:?}", self.state, e);
                self.state = SshConnectionState::Error;
            }
        };
        // log::info!("after parsing:\n{}", self_buffer.to_hex(16));
        ParseResult::Ok
    }
}

impl RParser for SshParser {
    fn parse_l4(&mut self, data: &[u8], direction: Direction) -> ParseResult {
        log::debug!("SSH current state: {:?}", self.state);
        match self.state {
            SshConnectionState::Start | SshConnectionState::CIdent => {
                self.parse_ident(data, direction)
            }
            SshConnectionState::SIdent
            | SshConnectionState::CKexInit
            | SshConnectionState::SKexInit
            | SshConnectionState::CKexDh
            | SshConnectionState::SKexDh
            | SshConnectionState::Established => self.parse_packet(data, direction),
            SshConnectionState::Error => ParseResult::Error,
            // _            => R_STATUS_FAIL,
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct SshKeyExchange {
    cookie: Vec<u8>,
    kex_algs: Vec<u8>,
    server_host_key_algs: Vec<u8>,
    encr_algs_client_to_server: Vec<u8>,
    encr_algs_server_to_client: Vec<u8>,
    mac_algs_client_to_server: Vec<u8>,
    mac_algs_server_to_client: Vec<u8>,
    comp_algs_client_to_server: Vec<u8>,
    comp_algs_server_to_client: Vec<u8>,
    langs_client_to_server: Vec<u8>,
    langs_server_to_client: Vec<u8>,
    first_kex_packet_follows: bool,
}

#[derive(Clone, Debug, Default)]
pub struct SshDhReply {
    pubkey_and_cert: Vec<u8>,
    f: Vec<u8>,
    signature: Vec<u8>,
}
