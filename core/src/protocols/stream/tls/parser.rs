//! TLS handshake parser.
//!
//! The TLS handshake parser uses a [fork](https://github.com/thegwan/tls-parser) of the
//! [tls-parser](https://docs.rs/tls-parser/latest/tls_parser/) crate to parse the handshake phase
//! of a TLS connection. It maintains TLS state, stores selected parameters, and handles
//! defragmentation.
//!
//! Adapted from [the Rusticata TLS
//! parser](https://github.com/rusticata/rusticata/blob/master/src/tls.rs).

use super::handshake::{
    Certificate, ClientDHParams, ClientECDHParams, ClientHello, ClientKeyExchange, ClientRSAParams,
    KeyShareEntry, ServerDHParams, ServerECDHParams, ServerHello, ServerKeyExchange,
    ServerRSAParams,
};
use super::Tls;
use crate::conntrack::conn::conn_info::ConnState;
use crate::conntrack::pdu::L4Pdu;
use crate::protocols::stream::{ConnParsable, ParseResult, ProbeResult, Session, SessionData};

use tls_parser::*;

/// Parses a single TLS handshake per connection.
#[derive(Debug)]
pub struct TlsParser {
    sessions: Vec<Tls>,
}

impl TlsParser {}

impl Default for TlsParser {
    fn default() -> Self {
        TlsParser {
            sessions: vec![Tls::new()],
        }
    }
}

impl ConnParsable for TlsParser {
    fn parse(&mut self, pdu: &L4Pdu) -> ParseResult {
        log::debug!("Updating parser tls");
        let offset = pdu.offset();
        let length = pdu.length();
        if length == 0 {
            return ParseResult::Skipped;
        }

        if let Ok(data) = (pdu.mbuf_ref()).get_data_slice(offset, length) {
            self.sessions[0].parse_tcp_level(data, pdu.dir)
        } else {
            log::warn!("Malformed packet");
            ParseResult::Skipped
        }
    }

    fn probe(&self, pdu: &L4Pdu) -> ProbeResult {
        if pdu.length() <= 2 {
            return ProbeResult::Unsure;
        }

        let offset = pdu.offset();
        let length = pdu.length();
        if let Ok(data) = (pdu.mbuf_ref()).get_data_slice(offset, length) {
            // First byte is record type (between 0x14 and 0x17, 0x16 is handhake) Second is TLS
            // version major (0x3) Third is TLS version minor (0x0 for SSLv3, 0x1 for TLSv1.0, etc.)
            // Does not support versions <= SSLv2
            match (data[0], data[1], data[2]) {
                (0x14..=0x17, 0x03, 0..=3) => ProbeResult::Certain,
                _ => ProbeResult::NotForUs,
            }
        } else {
            log::warn!("Malformed packet");
            ProbeResult::Error
        }
    }

    fn remove_session(&mut self, _session_id: usize) -> Option<Session> {
        self.sessions.pop().map(|tls| Session {
            data: SessionData::Tls(Box::new(tls)),
            id: 0,
        })
    }

    fn drain_sessions(&mut self) -> Vec<Session> {
        self.sessions
            .drain(..)
            .map(|tls| Session {
                data: SessionData::Tls(Box::new(tls)),
                id: 0,
            })
            .collect()
    }

    fn session_match_state(&self) -> ConnState {
        ConnState::Remove
    }

    fn session_nomatch_state(&self) -> ConnState {
        ConnState::Remove
    }
}

// ------------------------------------------------------------

impl Tls {
    /// Allocate a new TLS handshake instance.
    pub(crate) fn new() -> Tls {
        Tls {
            client_hello: None,
            server_hello: None,
            server_certificates: vec![],
            client_certificates: vec![],
            server_key_exchange: None,
            client_key_exchange: None,
            state: TlsState::None,
            tcp_buffer: vec![],
            record_buffer: vec![],
        }
    }

    /// Parse a ClientHello message.
    pub(crate) fn parse_handshake_clienthello(&mut self, content: &TlsClientHelloContents) {
        let mut client_hello = ClientHello {
            version: content.version,
            random: content.random.to_vec(),
            session_id: match content.session_id {
                Some(v) => v.to_vec(),
                None => vec![],
            },
            cipher_suites: content.ciphers.to_vec(),
            compression_algs: content.comp.to_vec(),
            ..ClientHello::default()
        };

        let ext = parse_tls_client_hello_extensions(content.ext.unwrap_or(b""));
        log::trace!("client extensions: {:#?}", ext);
        match &ext {
            Ok((rem, ref ext_lst)) => {
                if !rem.is_empty() {
                    log::debug!("warn: extensions not entirely parsed");
                }
                for extension in ext_lst {
                    client_hello
                        .extension_list
                        .push(TlsExtensionType::from(extension));
                    match *extension {
                        TlsExtension::SNI(ref v) => {
                            if !v.is_empty() {
                                let sni = v[0].1;
                                client_hello.server_name = Some(match std::str::from_utf8(sni) {
                                    Ok(name) => name.to_string(),
                                    Err(_) => format!("<Invalid UTF-8: {}>", hex::encode(sni)),
                                });
                            }
                        }
                        TlsExtension::SupportedGroups(ref v) => {
                            client_hello.supported_groups = v.clone();
                        }
                        TlsExtension::EcPointFormats(v) => {
                            client_hello.ec_point_formats = v.to_vec();
                        }
                        TlsExtension::SignatureAlgorithms(ref v) => {
                            client_hello.signature_algs = v.clone();
                        }
                        TlsExtension::ALPN(ref v) => {
                            for proto in v {
                                client_hello.alpn_protocols.push(
                                    match std::str::from_utf8(proto) {
                                        Ok(proto) => proto.to_string(),
                                        Err(_) => {
                                            format!("<Invalid UTF-8: {}>", hex::encode(proto))
                                        }
                                    },
                                );
                            }
                        }
                        TlsExtension::KeyShare(ref v) => {
                            log::debug!("Client Shares: {:?}", v);
                            client_hello.key_shares = v
                                .iter()
                                .map(|k| KeyShareEntry {
                                    group: k.group,
                                    kx_data: k.kx.to_vec(),
                                })
                                .collect();
                        }
                        TlsExtension::SupportedVersions(ref v) => {
                            client_hello.supported_versions = v.clone();
                        }
                        _ => (),
                    }
                }
            }
            e => log::debug!("Could not parse extensions: {:?}", e),
        };
        self.client_hello = Some(client_hello);
    }

    /// Parse a ServerHello message.
    fn parse_handshake_serverhello(&mut self, content: &TlsServerHelloContents) {
        let mut server_hello = ServerHello {
            version: content.version,
            random: content.random.to_vec(),
            session_id: match content.session_id {
                Some(v) => v.to_vec(),
                None => vec![],
            },
            cipher_suite: content.cipher,
            compression_alg: content.compression,
            ..ServerHello::default()
        };

        let ext = parse_tls_server_hello_extensions(content.ext.unwrap_or(b""));
        log::debug!("server_hello extensions: {:#?}", ext);
        match &ext {
            Ok((rem, ref ext_lst)) => {
                if !rem.is_empty() {
                    log::debug!("warn: extensions not entirely parsed");
                }
                for extension in ext_lst {
                    server_hello
                        .extension_list
                        .push(TlsExtensionType::from(extension));
                    match *extension {
                        TlsExtension::EcPointFormats(v) => {
                            server_hello.ec_point_formats = v.to_vec();
                        }
                        TlsExtension::ALPN(ref v) => {
                            if !v.is_empty() {
                                server_hello.alpn_protocol =
                                    Some(match std::str::from_utf8(v[0]) {
                                        Ok(proto) => proto.to_string(),
                                        Err(_) => format!("<Invalid UTF-8: {}>", hex::encode(v[0])),
                                    });
                            }
                        }
                        TlsExtension::KeyShare(ref v) => {
                            log::debug!("Server Share: {:?}", v);
                            if !v.is_empty() {
                                server_hello.key_share = Some(KeyShareEntry {
                                    group: v[0].group,
                                    kx_data: v[0].kx.to_vec(),
                                });
                            }
                        }
                        TlsExtension::SupportedVersions(ref v) => {
                            if !v.is_empty() {
                                server_hello.selected_version = Some(v[0]);
                            }
                        }
                        _ => (),
                    }
                }
            }
            e => log::debug!("Could not parse extensions: {:?}", e),
        };
        self.server_hello = Some(server_hello);
    }

    /// Parse a Certificate message.
    fn parse_handshake_certificate(&mut self, content: &TlsCertificateContents, direction: bool) {
        log::trace!("cert chain length: {}", content.cert_chain.len());
        if direction {
            // client -> server
            for cert in &content.cert_chain {
                self.client_certificates.push(Certificate {
                    raw: cert.data.to_vec(),
                })
            }
        } else {
            // server -> client
            for cert in &content.cert_chain {
                self.server_certificates.push(Certificate {
                    raw: cert.data.to_vec(),
                })
            }
        }
    }

    /// Parse a ServerKeyExchange message.
    fn parse_handshake_serverkeyexchange(&mut self, content: &TlsServerKeyExchangeContents) {
        log::trace!("SKE: {:?}", content);
        if let Some(cipher) = self.cipher_suite() {
            match &cipher.kx {
                TlsCipherKx::Ecdhe | TlsCipherKx::Ecdh => {
                    if let Ok((_sig, ref parsed)) = parse_server_ecdh_params(content.parameters) {
                        if let ECParametersContent::NamedGroup(curve) =
                            parsed.curve_params.params_content
                        {
                            let ecdh_params = ServerECDHParams {
                                curve,
                                kx_data: parsed.public.point.to_vec(),
                            };
                            self.server_key_exchange = Some(ServerKeyExchange::Ecdh(ecdh_params));
                        };
                    }
                }
                TlsCipherKx::Dhe | TlsCipherKx::Dh => {
                    if let Ok((_sig, ref parsed)) = parse_server_dh_params(content.parameters) {
                        let dh_params = ServerDHParams {
                            prime: parsed.dh_p.to_vec(),
                            generator: parsed.dh_g.to_vec(),
                            kx_data: parsed.dh_ys.to_vec(),
                        };
                        self.server_key_exchange = Some(ServerKeyExchange::Dh(dh_params));
                    }
                }
                TlsCipherKx::Rsa => {
                    if let Ok((_sig, ref parsed)) = parse_server_rsa_params(content.parameters) {
                        let rsa_params = ServerRSAParams {
                            modulus: parsed.modulus.to_vec(),
                            exponent: parsed.exponent.to_vec(),
                        };
                        self.server_key_exchange = Some(ServerKeyExchange::Rsa(rsa_params));
                    }
                }
                _ => {
                    self.server_key_exchange =
                        Some(ServerKeyExchange::Unknown(content.parameters.to_vec()))
                }
            }
        }
    }

    /// Parse a ClientKeyExchange message.
    fn parse_handshake_clientkeyexchange(&mut self, content: &TlsClientKeyExchangeContents) {
        log::trace!("CKE: {:?}", content);
        if let Some(cipher) = self.cipher_suite() {
            match &cipher.kx {
                TlsCipherKx::Ecdhe | TlsCipherKx::Ecdh => {
                    if let Ok((_rem, ref parsed)) = parse_client_ecdh_params(content.parameters) {
                        let ecdh_params = ClientECDHParams {
                            kx_data: parsed.ecdh_yc.point.to_vec(),
                        };
                        self.client_key_exchange = Some(ClientKeyExchange::Ecdh(ecdh_params));
                    }
                }
                TlsCipherKx::Dhe | TlsCipherKx::Dh => {
                    if let Ok((_rem, ref parsed)) = parse_client_dh_params(content.parameters) {
                        let dh_params = ClientDHParams {
                            kx_data: parsed.dh_yc.to_vec(),
                        };
                        self.client_key_exchange = Some(ClientKeyExchange::Dh(dh_params));
                    }
                }
                TlsCipherKx::Rsa => {
                    if let Ok((_rem, ref parsed)) = parse_client_rsa_params(content.parameters) {
                        let rsa_params = ClientRSAParams {
                            encrypted_pms: parsed.data.to_vec(),
                        };
                        self.client_key_exchange = Some(ClientKeyExchange::Rsa(rsa_params));
                    }
                }
                _ => {
                    self.client_key_exchange =
                        Some(ClientKeyExchange::Unknown(content.parameters.to_vec()))
                }
            }
        }
        //self.client_key_exchange = Some(client_key_exchange);
    }

    /// Parse a TLS message.
    pub(crate) fn parse_message_level(&mut self, msg: &TlsMessage, direction: bool) -> ParseResult {
        log::trace!("parse_message_level {:?}", msg);

        // do not parse if session is encrypted
        if self.state == TlsState::ClientChangeCipherSpec {
            log::trace!("TLS session encrypted, activating bypass");
            return ParseResult::Done(0);
        }

        // update state machine
        match tls_state_transition(self.state, msg, direction) {
            Ok(s) => self.state = s,
            Err(_) => {
                self.state = TlsState::Invalid;
            }
        };
        log::trace!("TLS new state: {:?}", self.state);

        // extract variables
        match *msg {
            TlsMessage::Handshake(ref m) => match *m {
                TlsMessageHandshake::ClientHello(ref content) => {
                    self.parse_handshake_clienthello(content);
                }
                TlsMessageHandshake::ServerHello(ref content) => {
                    self.parse_handshake_serverhello(content);
                }
                TlsMessageHandshake::Certificate(ref content) => {
                    self.parse_handshake_certificate(content, direction);
                }
                TlsMessageHandshake::ServerKeyExchange(ref content) => {
                    self.parse_handshake_serverkeyexchange(content);
                }
                TlsMessageHandshake::ClientKeyExchange(ref content) => {
                    self.parse_handshake_clientkeyexchange(content);
                }

                _ => (),
            },
            TlsMessage::Alert(ref a) => {
                if a.severity == TlsAlertSeverity::Fatal {
                    return ParseResult::Done(0);
                }
            }
            _ => (),
        }

        ParseResult::Continue(0)
    }

    /// Parse a TLS record.
    pub(crate) fn parse_record_level(
        &mut self,
        record: &TlsRawRecord<'_>,
        direction: bool,
    ) -> ParseResult {
        let mut v: Vec<u8>;
        let mut status = ParseResult::Continue(0);

        log::trace!("parse_record_level ({} bytes)", record.data.len());
        log::trace!("{:?}", record.hdr);
        // log::trace!("{:?}", record.data);

        // do not parse if session is encrypted
        if self.state == TlsState::ClientChangeCipherSpec {
            log::trace!("TLS session encrypted, activating bypass");
            return ParseResult::Done(0);
        }

        // only parse some message types (the Content type, first byte of TLS record)
        match record.hdr.record_type {
            TlsRecordType::ChangeCipherSpec => (),
            TlsRecordType::Handshake => (),
            TlsRecordType::Alert => (),
            _ => return ParseResult::Continue(0),
        }

        // Check if a record is being defragmented
        let record_buffer = match self.record_buffer.len() {
            0 => record.data,
            _ => {
                // sanity check vector length to avoid memory exhaustion maximum length may be 2^24
                // (handshake message)
                if self.record_buffer.len() + record.data.len() > 16_777_216 {
                    return ParseResult::Skipped;
                };
                v = self.record_buffer.split_off(0);
                v.extend_from_slice(record.data);
                v.as_slice()
            }
        };

        // TODO: record may be compressed Parse record contents as plaintext
        match parse_tls_record_with_header(record_buffer, &record.hdr) {
            Ok((rem, ref msg_list)) => {
                for msg in msg_list {
                    status = self.parse_message_level(msg, direction);
                    if status != ParseResult::Continue(0) {
                        return status;
                    }
                }
                if !rem.is_empty() {
                    log::debug!("warn: extra bytes in TLS record: {:?}", rem);
                };
            }
            Err(Err::Incomplete(needed)) => {
                log::trace!(
                    "Defragmentation required (TLS record), missing {:?} bytes",
                    needed
                );
                self.record_buffer.extend_from_slice(record.data);
            }
            Err(_e) => {
                log::debug!("warn: parse_tls_record_with_header failed");
                return ParseResult::Skipped;
            }
        };

        status
    }

    /// Parse a TCP segment, handling TCP chunks fragmentation.
    pub(crate) fn parse_tcp_level(&mut self, data: &[u8], direction: bool) -> ParseResult {
        let mut v: Vec<u8>;
        let mut status = ParseResult::Continue(0);
        log::trace!("parse_tcp_level ({} bytes)", data.len());
        log::trace!("defrag buffer size: {}", self.tcp_buffer.len());

        // do not parse if session is encrypted
        if self.state == TlsState::ClientChangeCipherSpec {
            log::trace!("TLS session encrypted, activating bypass");
            return ParseResult::Done(0);
        };
        // Check if TCP data is being defragmented
        let tcp_buffer = match self.tcp_buffer.len() {
            0 => data,
            _ => {
                // sanity check vector length to avoid memory exhaustion maximum length may be 2^24
                // (handshake message)
                if self.tcp_buffer.len() + data.len() > 16_777_216 {
                    return ParseResult::Skipped;
                };
                v = self.tcp_buffer.split_off(0);
                v.extend_from_slice(data);
                v.as_slice()
            }
        };
        let mut cur_data = tcp_buffer;
        while !cur_data.is_empty() {
            // parse each TLS record in the TCP segment (there could be multiple)
            match parse_tls_raw_record(cur_data) {
                Ok((rem, ref record)) => {
                    cur_data = rem;
                    status = self.parse_record_level(record, direction);
                    if status != ParseResult::Continue(0) {
                        return status;
                    }
                }
                Err(Err::Incomplete(needed)) => {
                    log::trace!(
                        "Defragmentation required (TCP level), missing {:?} bytes",
                        needed
                    );
                    self.tcp_buffer.extend_from_slice(cur_data);
                    break;
                }
                Err(_e) => {
                    log::debug!("warn: Parsing raw record failed");
                    break;
                }
            }
        }
        status
    }
}
