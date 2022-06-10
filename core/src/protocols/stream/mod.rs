//! Types for parsing and manipulating stream-level network protocols.
//!
//! Any protocol that requires parsing over multiple packets within a single connection or flow is
//! considered a "stream-level" protocol, even if it is a datagram-based protocol in the
//! traditional-sense.

pub mod dns;
pub mod http;
pub mod tls;

use self::dns::{parser::DnsParser, Dns};
use self::http::{parser::HttpParser, Http};
use self::tls::{parser::TlsParser, Tls};
use crate::conntrack::conn::conn_info::ConnState;
use crate::conntrack::conn_id::FiveTuple;
use crate::conntrack::pdu::L4Pdu;
use crate::filter::Filter;
use crate::subscription::*;

use std::str::FromStr;

use anyhow::{bail, Result};
use strum_macros::EnumString;

/// Represents the result of parsing one packet as a protocol message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ParseResult {
    /// Session parsing done, check session filter. Returns the most-recently-updated session ID.
    Done(usize),
    /// Successfully extracted data, continue processing more packets. Returns most recently updated
    /// session ID.
    Continue(usize),
    /// Parsing skipped, no data extracted.
    Skipped,
}

/// Represents the result of a probing one packet as a protocol message type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProbeResult {
    /// Segment matches the parser with great probability.
    Certain,
    /// Unsure if the segment matches the parser.
    Unsure,
    /// Segment does not match the parser.
    NotForUs,
    /// Error occurred during the probe. Functionally equivalent to Unsure.
    Error,
}

/// Represents the result of probing one packet with all registered protocol parsers.
#[derive(Debug)]
pub(crate) enum ProbeRegistryResult {
    /// A parser in the registry was definitively matched.
    Some(ConnParser),
    /// All parsers in the registry were definitively not matched.
    None,
    /// Unsure, continue sending more data.
    Unsure,
}

/// The set of application-layer protocol parsers required to fulfill the subscription.
#[derive(Debug)]
pub(crate) struct ParserRegistry(Vec<ConnParser>);

impl ParserRegistry {
    /// Builds a new `ParserRegistry` from the `filter` and tracked subscribable type `T`.
    pub(crate) fn build<T: Subscribable>(filter: &Filter) -> Result<ParserRegistry> {
        let parsers = T::parsers();
        if !parsers.is_empty() {
            return Ok(ParserRegistry(parsers));
        }

        let mut stream_protocols = hashset! {};
        for pattern in filter.get_patterns_flat().iter() {
            for predicate in pattern.predicates.iter() {
                if predicate.on_connection() {
                    stream_protocols.insert(predicate.get_protocol().to_owned());
                }
            }
        }

        let mut parsers = vec![];
        for stream_protocol in stream_protocols.iter() {
            if let Ok(parser) = ConnParser::from_str(stream_protocol.name()) {
                parsers.push(parser);
            } else {
                bail!("Unknown application-layer protocol");
            }
        }
        Ok(ParserRegistry(parsers))
    }

    /// Probe the packet `pdu` with all registered protocol parsers.
    pub(crate) fn probe_all(&self, pdu: &L4Pdu) -> ProbeRegistryResult {
        if self.0.is_empty() {
            return ProbeRegistryResult::None;
        }
        if pdu.length() == 0 {
            return ProbeRegistryResult::Unsure;
        }

        let mut num_notmatched = 0;
        for parser in self.0.iter() {
            match parser.probe(pdu) {
                ProbeResult::Certain => {
                    return ProbeRegistryResult::Some(parser.reset_new());
                }
                ProbeResult::NotForUs => {
                    num_notmatched += 1;
                }
                _ => (), // Unsure, Error, Reverse
            }
        }
        if num_notmatched == self.0.len() {
            ProbeRegistryResult::None
        } else {
            ProbeRegistryResult::Unsure
        }
    }
}

/// A trait all application-layer protocol parsers must implement.
pub(crate) trait ConnParsable {
    /// Parse the L4 protocol data unit as the parser's protocol.
    fn parse(&mut self, pdu: &L4Pdu) -> ParseResult;

    /// Probe if the L4 protocol data unit matches the parser's protocol.
    fn probe(&self, pdu: &L4Pdu) -> ProbeResult;

    /// Removes session with ID `session_id` and returns it.
    fn remove_session(&mut self, session_id: usize) -> Option<Session>;

    /// Removes all sessions in the connection parser and returns them.
    fn drain_sessions(&mut self) -> Vec<Session>;

    /// Default state to set the tracked connection to on a matched session.
    fn session_match_state(&self) -> ConnState;

    /// Default state to set the tracked connection to on a non-matched session.
    fn session_nomatch_state(&self) -> ConnState;
}

/// Data required to filter on connections.
///
/// ## Note
/// This must have `pub` visibility because it needs to be accessible by the
/// [retina_filtergen](fixlink) crate. At time of this writing, procedural macros must be defined in
/// a separate crate, so items that ought to be crate-private have their documentation hidden to
/// avoid confusing users.
#[doc(hidden)]
#[derive(Debug)]
pub struct ConnData {
    /// The connection 5-tuple.
    pub five_tuple: FiveTuple,
    /// The protocol parser associated with the connection.
    pub conn_parser: ConnParser,
    /// Packet terminal node ID matched by first packet of connection.
    pub pkt_term_node: usize,
    /// Connection terminal node ID matched by connection after successful probe. If packet terminal
    /// node is terminal, this is the same as the packet terminal node.
    pub conn_term_node: usize,
}

impl ConnData {
    /// Create a new `ConnData` from the connection `five_tuple` and the ID of the last matched node
    /// in the filter predicate trie.
    pub(crate) fn new(five_tuple: FiveTuple, pkt_term_node: usize) -> Self {
        ConnData {
            five_tuple,
            conn_parser: ConnParser::Unknown,
            pkt_term_node,
            conn_term_node: pkt_term_node,
        }
    }

    /// Returns the application-layer protocol parser associated with the connection.
    pub fn service(&self) -> &ConnParser {
        &self.conn_parser
    }
}

/// Data required to filter on application-layer protocol sessions.
///
/// ## Note
/// This must have `pub` visibility because it needs to be accessible by the
/// [retina_filtergen](fixlink) crate. At time of this writing, procedural macros must be defined in
/// a separate crate, so items that ought to be crate-private have their documentation hidden to
/// avoid confusing users.
#[doc(hidden)]
#[derive(Debug)]
pub enum SessionData {
    // TODO: refactor to use trait objects.
    Tls(Box<Tls>),
    Dns(Box<Dns>),
    Http(Box<Http>),
    Null,
}

/// An application-layer protocol session.
///
/// ## Note
/// This must have `pub` visibility because it needs to be accessible by the
/// [retina_filtergen](fixlink) crate. At time of this writing, procedural macros must be defined in
/// a separate crate, so items that ought to be crate-private have their documentation hidden to
/// avoid confusing users.
#[doc(hidden)]
pub struct Session {
    /// Application-layer session data.
    pub data: SessionData,
    /// A unique identifier that represents the arrival order of the first packet of the session.
    pub id: usize,
}

impl Default for Session {
    fn default() -> Self {
        Session {
            data: SessionData::Null,
            id: 0,
        }
    }
}

/// A connection protocol parser.
///
/// ## Note
/// This must have `pub` visibility because it needs to be accessible by the
/// [retina_filtergen](fixlink) crate. At time of this writing, procedural macros must be defined in
/// a separate crate, so items that ought to be crate-private have their documentation hidden to
/// avoid confusing users.
#[doc(hidden)]
#[derive(Debug, EnumString)]
#[strum(serialize_all = "snake_case")]
pub enum ConnParser {
    // TODO: refactor to use trait objects.
    Tls(TlsParser),
    Dns(DnsParser),
    Http(HttpParser),
    Unknown,
}

impl ConnParser {
    /// Returns a new connection protocol parser of the same type, but with state reset.
    pub(crate) fn reset_new(&self) -> ConnParser {
        match self {
            ConnParser::Tls(_) => ConnParser::Tls(TlsParser::default()),
            ConnParser::Dns(_) => ConnParser::Dns(DnsParser::default()),
            ConnParser::Http(_) => ConnParser::Http(HttpParser::default()),
            ConnParser::Unknown => ConnParser::Unknown,
        }
    }

    /// Returns the result of parsing `pdu` as a protocol message.
    pub(crate) fn parse(&mut self, pdu: &L4Pdu) -> ParseResult {
        match self {
            ConnParser::Tls(parser) => parser.parse(pdu),
            ConnParser::Dns(parser) => parser.parse(pdu),
            ConnParser::Http(parser) => parser.parse(pdu),
            ConnParser::Unknown => ParseResult::Skipped,
        }
    }

    /// Returns the result of probing whether `pdu` is a protocol message.
    pub(crate) fn probe(&self, pdu: &L4Pdu) -> ProbeResult {
        match self {
            ConnParser::Tls(parser) => parser.probe(pdu),
            ConnParser::Dns(parser) => parser.probe(pdu),
            ConnParser::Http(parser) => parser.probe(pdu),
            ConnParser::Unknown => ProbeResult::Error,
        }
    }

    /// Removes the session with ID `session_id` from any protocol state managed by the parser, and
    /// returns it.
    pub(crate) fn remove_session(&mut self, session_id: usize) -> Option<Session> {
        match self {
            ConnParser::Tls(parser) => parser.remove_session(session_id),
            ConnParser::Dns(parser) => parser.remove_session(session_id),
            ConnParser::Http(parser) => parser.remove_session(session_id),
            ConnParser::Unknown => None,
        }
    }

    /// Removes all remaining sessions managed by the parser and returns them.
    pub(crate) fn drain_sessions(&mut self) -> Vec<Session> {
        match self {
            ConnParser::Tls(parser) => parser.drain_sessions(),
            ConnParser::Dns(parser) => parser.drain_sessions(),
            ConnParser::Http(parser) => parser.drain_sessions(),
            ConnParser::Unknown => vec![],
        }
    }

    /// Returns the state that a connection should transition to on a session filter match.
    pub(crate) fn session_match_state(&self) -> ConnState {
        match self {
            ConnParser::Tls(parser) => parser.session_match_state(),
            ConnParser::Dns(parser) => parser.session_match_state(),
            ConnParser::Http(parser) => parser.session_match_state(),
            ConnParser::Unknown => ConnState::Remove,
        }
    }

    /// Returns the state that a connection should transition to on a failed session filter match.
    pub(crate) fn session_nomatch_state(&self) -> ConnState {
        match self {
            ConnParser::Tls(parser) => parser.session_nomatch_state(),
            ConnParser::Dns(parser) => parser.session_nomatch_state(),
            ConnParser::Http(parser) => parser.session_nomatch_state(),
            ConnParser::Unknown => ConnState::Remove,
        }
    }
}
