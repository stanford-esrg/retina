// Borrowed from https://github.com/rusticata/rusticata/blob/master/src/dns_udp.rs
//! DNS transaction parser.
//!
//! The DNS transaction parser uses a [fork](https://github.com/thegwan/dns-parser) of the
//! [dns-parser](https://docs.rs/dns-parser/latest/dns_parser/) crate to parse DNS queries and
//! responses. It maintains state for tracking outstanding queries and linking query/response pairs.
//!
//! Adapted from [the Rusticata DNS
//! parser](https://github.com/rusticata/rusticata/blob/master/src/dns_udp.rs).

use super::transaction::{DnsQuery, DnsResponse};
use super::Dns;
use crate::conntrack::conn::conn_info::ConnState;
use crate::conntrack::pdu::L4Pdu;
use crate::protocols::stream::{ConnParsable, ParseResult, ProbeResult, Session, SessionData};

use std::collections::HashMap;

#[derive(Default, Debug)]
pub struct DnsParser {
    /// Maps session ID to DNS transaction
    sessions: HashMap<usize, Dns>,
    /// Total sessions ever seen (Running session ID)
    cnt: usize,
}

impl ConnParsable for DnsParser {
    fn parse(&mut self, pdu: &L4Pdu) -> ParseResult {
        let offset = pdu.offset();
        let length = pdu.length();
        if length == 0 {
            return ParseResult::Skipped;
        }

        if let Ok(data) = (pdu.mbuf_ref()).get_data_slice(offset, length) {
            self.process(data)
        } else {
            log::warn!("Malformed packet");
            ParseResult::Skipped
        }
    }

    fn probe(&self, pdu: &L4Pdu) -> ProbeResult {
        let dst_port = pdu.ctxt.dst.port();
        let src_port = pdu.ctxt.src.port();
        if src_port == 137 || dst_port == 137 {
            // NetBIOS NBSS looks like DNS, but parser will fail on labels
            return ProbeResult::NotForUs;
        }
        let offset = pdu.offset();
        let length = pdu.length();
        if pdu.length() == 0 {
            return ProbeResult::Unsure;
        }

        if let Ok(data) = (pdu.mbuf).get_data_slice(offset, length) {
            match dns_parser::Packet::parse(data) {
                Ok(packet) => {
                    if packet.header.query {
                        if packet.questions.is_empty() {
                            return ProbeResult::NotForUs;
                        }
                    } else if packet.answers.is_empty() {
                        return ProbeResult::NotForUs;
                    }
                    ProbeResult::Certain
                }
                _ => ProbeResult::NotForUs,
            }
        } else {
            log::warn!("Malformed packet");
            ProbeResult::Error
        }
    }

    fn remove_session(&mut self, session_id: usize) -> Option<Session> {
        self.sessions.remove(&session_id).map(|dns| Session {
            data: SessionData::Dns(Box::new(dns)),
            id: session_id,
        })
    }

    fn drain_sessions(&mut self) -> Vec<Session> {
        self.sessions
            .drain()
            .map(|(session_id, dns)| Session {
                data: SessionData::Dns(Box::new(dns)),
                id: session_id,
            })
            .collect()
    }

    fn session_match_state(&self) -> ConnState {
        ConnState::Parsing
    }

    fn session_nomatch_state(&self) -> ConnState {
        ConnState::Parsing
    }
}

impl DnsParser {
    pub(crate) fn process(&mut self, data: &[u8]) -> ParseResult {
        match dns_parser::Packet::parse(data) {
            Ok(pkt) => {
                if pkt.header.query {
                    log::debug!("DNS query");
                    let query = DnsQuery::parse_query(&pkt);
                    let query_id = pkt.header.id;
                    for (session_id, dns) in self.sessions.iter_mut() {
                        if query_id == dns.transaction_id {
                            if dns.response.is_some() {
                                dns.query = Some(query);
                                return ParseResult::Done(*session_id);
                            }
                            break;
                        }
                    }
                    let dns = Dns {
                        transaction_id: query_id,
                        query: Some(query),
                        response: None,
                    };
                    let session_id = self.cnt;
                    self.cnt += 1;
                    self.sessions.insert(session_id, dns);
                    ParseResult::Continue(session_id)
                } else {
                    log::debug!("DNS answer");
                    let response = DnsResponse::parse_response(&pkt);
                    let answer_id = pkt.header.id;
                    for (session_id, dns) in self.sessions.iter_mut() {
                        if answer_id == dns.transaction_id {
                            if dns.query.is_some() {
                                dns.response = Some(response);
                                return ParseResult::Done(*session_id);
                            }
                            break;
                        }
                    }
                    let dns = Dns {
                        transaction_id: answer_id,
                        query: None,
                        response: Some(response),
                    };
                    let session_id = self.cnt;
                    self.cnt += 1;
                    self.sessions.insert(session_id, dns);
                    ParseResult::Continue(session_id)
                }
            }
            e => {
                log::debug!("parse error: {:?}", e);
                ParseResult::Skipped
            }
        }
    }
}
