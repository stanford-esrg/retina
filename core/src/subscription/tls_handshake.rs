//! TLS handshakes.
//!
//! This is a session-level subscription that delivers parsed TLS handshakes and associated
//! connection metadata. Only the first TLS handshake in a connection is parsed; subsequent
//! encrypted messages are dropped.
//!
//! ## Example
//! Prints the chosen cipher suite of TLS handshakes with `calendar.google.com`.
//! ```
//! #[filter("tls.sni = 'calendar.google.com'")]
//! fn main() {
//!     let config = default_config();
//!     let cb = |tls: TlsHandshake| {
//!         println!("{}", tls.data.cipher());
//!     };
//!     let mut runtime = Runtime::new(config, filter, cb).unwrap();
//!     runtime.run();
//! }

use crate::conntrack::conn_id::FiveTuple;
use crate::conntrack::pdu::{L4Context, L4Pdu};
use crate::conntrack::ConnTracker;
use crate::filter::{FilterResult, FilterResultData};
use crate::memory::mbuf::Mbuf;
use crate::protocols::stream::tls::{parser::TlsParser, Tls};
use crate::protocols::stream::{ConnParser, Session, SessionData, ConnData};
use crate::conntrack::conn::conn_info::ConnState;
use crate::subscription::{Subscribable, Subscription, Trackable, MatchData};

use serde::Serialize;

use std::net::SocketAddr;

/// A parsed TLS handshake and connection metadata.
#[derive(Debug, Serialize)]
pub struct TlsHandshake {
    /// Connection 5-tuple.
    pub five_tuple: FiveTuple,
    /// Parsed TLS handshake data.
    pub data: Tls,
}

impl TlsHandshake {
    /// Returns the client's socket address.
    #[inline]
    pub fn client(&self) -> SocketAddr {
        self.five_tuple.orig
    }

    /// Returns the server's socket address.
    #[inline]
    pub fn server(&self) -> SocketAddr {
        self.five_tuple.resp
    }
}

pub struct TlsHandshakeSubscription;

impl Subscribable for TlsHandshakeSubscription {
    type Tracked = TrackedTls;
    type SubscribedData = TlsHandshake;

    fn parsers() -> Vec<ConnParser> {
        vec![ConnParser::Tls(TlsParser::default())]
    }

    fn process_packet(
        mbuf: Mbuf,
        subscription: &Subscription<Self>,
        conn_tracker: &mut ConnTracker<Self::Tracked>,
    ) {
       let result = subscription.filter_packet(&mbuf);
        if result.terminal_matches != 0 || result.nonterminal_matches != 0 {
            if let Ok(ctxt) = L4Context::new(&mbuf) {
                conn_tracker.process(mbuf, ctxt, subscription, result);
            }
        } else {
            drop(mbuf);
        }
    }
}

/// Represents TLS connection's state during the connection lifetime.
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
pub struct TrackedTls {
    five_tuple: FiveTuple,
    match_data: MatchData,
}

impl Trackable for TrackedTls {
    type Subscribed = TlsHandshakeSubscription;

    fn new(five_tuple: FiveTuple, pkt_results: FilterResultData) -> Self {
        TrackedTls { 
            five_tuple, 
            match_data: MatchData::new(pkt_results),
        }
    }

    fn deliver_session_on_match(&mut self, session: Session, 
                                subscription: &Subscription<Self::Subscribed>) -> ConnState {
        if let SessionData::Tls(tls) = session.data {
            subscription.invoke( 
                TlsHandshake {
                    five_tuple: self.five_tuple,
                    data: *tls,
                }
            );
        }
        ConnState::Remove
    }

    fn update(&mut self, 
              _pdu: L4Pdu, 
              _session_id: Option<usize>,
              _subscription: &Subscription<Self::Subscribed>) {}

    fn on_terminate(&mut self, _subscription: &Subscription<Self::Subscribed>) {}

    fn filter_packet(&mut self, pkt_filter_result: FilterResultData) {
        self.match_data.filter_packet(pkt_filter_result);
    }

    fn filter_conn(&mut self, conn: &ConnData, subscription:  &Subscription<Self::Subscribed>) -> FilterResult {
        return self.match_data.filter_conn(conn, subscription);
    }
    fn filter_session(&mut self, session: &Session, subscription: &Subscription<Self::Subscribed>) -> bool {
        return self.match_data.filter_session(session, subscription);
    }
}
