//! QUIC streams.
//!
//! This is a session-level subscription that delivers parsed QUIC stream records and associated
//! connection metadata.
//!
//! ## Example
//! Prints QUIC connections that use long headers:
//! ```
//! #[filter("quic.header_type = 'long'")]
//! fn main() {
//!     let config = default_config();
//!     let cb = |quic: QuicStream| {
//!         println!("{}", quic.data);
//!     };
//!     let mut runtime = Runtime::new(config, filter, cb).unwrap();
//!     runtime.run();
//! }

use crate::conntrack::conn_id::FiveTuple;
use crate::conntrack::pdu::{L4Context, L4Pdu};
use crate::conntrack::ConnTracker;
use crate::filter::FilterResult;
use crate::memory::mbuf::Mbuf;
use crate::protocols::stream::quic::{parser::QuicParser, QuicPacket};
use crate::protocols::stream::{ConnParser, Session, SessionData};
use crate::subscription::{Level, Subscribable, Subscription, Trackable};
use std::collections::HashSet;

use serde::Serialize;

use std::net::SocketAddr;

/// A parsed QUIC stream and connection metadata.
#[derive(Debug, Serialize)]
pub struct QuicStream {
    pub five_tuple: FiveTuple,
    pub data: QuicPacket,
}

impl QuicStream {
    /// Returns the QUIC client's socket address.
    #[inline]
    pub fn client(&self) -> SocketAddr {
        self.five_tuple.orig
    }

    /// Returns the QUIC server's socket address.
    #[inline]
    pub fn server(&self) -> SocketAddr {
        self.five_tuple.resp
    }
}

impl Subscribable for QuicStream {
    type Tracked = TrackedQuic;

    fn level() -> Level {
        Level::Session
    }

    fn parsers() -> Vec<ConnParser> {
        vec![ConnParser::Quic(QuicParser::default())]
    }

    fn process_packet(
        mbuf: Mbuf,
        subscription: &Subscription<Self>,
        conn_tracker: &mut ConnTracker<Self::Tracked>,
    ) {
        match subscription.filter_packet(&mbuf) {
            FilterResult::MatchTerminal(idx) | FilterResult::MatchNonTerminal(idx) => {
                if let Ok(ctxt) = L4Context::new(&mbuf, idx) {
                    conn_tracker.process(mbuf, ctxt, subscription);
                }
            }
            FilterResult::NoMatch => drop(mbuf),
        }
    }
}

/// Represents a QUIC connection during the connection lifetime.
///
/// ## Remarks
/// Retina uses an internal parser to track and filter application-layer protocols, and transfers
/// session ownership to the subscription to invoke the callback on a filter match. This is an
/// optimization to avoid double-parsing: once for the filter and once for the subscription data.
/// This is why most `Trackable` trait methods for this type are unimplemented.
///
/// ## Note
/// Internal connection state is an associated type of a `pub` trait, and therefore must also be
/// public. Documentation is hidden by default to avoid confusing users.
#[doc(hidden)]
pub struct TrackedQuic {
    five_tuple: FiveTuple,
    connection_id: HashSet<String>,
}

impl TrackedQuic {
    fn get_connection_id(&self, dcid_bytes: &[u8]) -> Option<String> {
        let dcid_hex = QuicPacket::vec_u8_to_hex_string(dcid_bytes);
        for dcid in &self.connection_id {
            if dcid_hex.starts_with(dcid) {
                return Some(dcid.clone());
            }
        }
        None
    }
}

impl Trackable for TrackedQuic {
    type Subscribed = QuicStream;

    fn new(five_tuple: FiveTuple) -> Self {
        TrackedQuic {
            five_tuple,
            connection_id: HashSet::new(),
        }
    }

    fn pre_match(&mut self, _pdu: L4Pdu, _session_id: Option<usize>) {}

    fn on_match(&mut self, session: Session, subscription: &Subscription<Self::Subscribed>) {
        if let SessionData::Quic(quic) = session.data {
            let mut quic_clone = *quic;

            if let Some(long_header) = &quic_clone.long_header {
                if long_header.dcid_len > 0 {
                    self.connection_id.insert(long_header.dcid.clone());
                }
                if long_header.scid_len > 0 {
                    self.connection_id.insert(long_header.scid.clone());
                }
            } else {
                if let Some(ref mut short_header_value) = quic_clone.short_header {
                    short_header_value.dcid =
                        self.get_connection_id(&short_header_value.dcid_bytes);
                }
                return subscription.invoke(QuicStream {
                    five_tuple: self.five_tuple,
                    data: quic_clone,
                });
            }

            subscription.invoke(QuicStream {
                five_tuple: self.five_tuple,
                data: quic_clone,
            });
        }
    }

    fn post_match(&mut self, _pdu: L4Pdu, _subscription: &Subscription<Self::Subscribed>) {}

    fn on_terminate(&mut self, _subscription: &Subscription<Self::Subscribed>) {
        self.connection_id.clear();
    }
}
