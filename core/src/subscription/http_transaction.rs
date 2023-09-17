//! HTTP transactions.
//!
//! This is a session-level subscription that delivers parsed HTTP transaction records and
//! associated connection metadata.
//!
//! ## Example
//! Counts the number of HTTP `GET` requests with a user agent containing `Safari`:
//! ```
//! #[filter("http.method = 'GET' and http.user_agent ~ 'Safari'")]
//! fn main() {
//!     let config = default_config();
//!     let cnt = AtomicUsize::new(0);
//!     let cb = |_http: HttpTransaction| {
//!         cnt.fetch_add(1, Ordering::Relaxed);
//!     };
//!     let mut runtime = Runtime::new(config, filter, cb).unwrap();
//!     runtime.run();
//!     println!("Count: {:?}", cnt);
//! }

use crate::conntrack::conn_id::FiveTuple;
use crate::conntrack::pdu::{L4Context, L4Pdu};
use crate::conntrack::ConnTracker;
use crate::conntrack::conn::conn_info::ConnState;
use crate::filter::{FilterResultData, FilterResult};
use crate::memory::mbuf::Mbuf;
use crate::protocols::stream::http::{parser::HttpParser, Http};
use crate::protocols::stream::{ConnParser, Session, SessionData, ConnData};
use crate::subscription::{Subscribable, Subscription, Trackable, MatchData};

use serde::Serialize;

use std::net::SocketAddr;

/// A parsed HTTP transaction and connection metadata.
#[derive(Debug, Serialize)]
pub struct HttpTransaction {
    pub five_tuple: FiveTuple,
    pub data: Http,
}

impl HttpTransaction {
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

pub struct HttpTransactionSubscription;

impl Subscribable for HttpTransactionSubscription {
    type Tracked = TrackedHttp;
    type SubscribedData = HttpTransaction;

    fn parsers() -> Vec<ConnParser> {
        vec![ConnParser::Http(HttpParser::default())]
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

/// Represents an HTTP connection's state during the connection lifetime.
///
/// ## Remarks
/// Retina uses an internal parser to track and filter application-layer protocols, and transfers
/// session ownership to the subscription to invoke the callback on a filter match. This is an
/// optimization to avoid double-parsing: once for the filter and once for the subscription data.
/// This is why most `Trackable` trait methods for this type are unimplemented.
///
/// ## Note
/// Internal connection state is an associated type of a `pub` trait, and therefore must also be
/// public. Currently, we hide its documentation to avoid confusing users. TODO: A future workaround
/// could be to split the trait into a public and private part.
#[doc(hidden)]
pub struct TrackedHttp {
    five_tuple: FiveTuple,
    match_data: MatchData,
}

impl Trackable for TrackedHttp {
    type Subscribed = HttpTransactionSubscription;

    fn new(five_tuple: FiveTuple, pkt_results: FilterResultData) -> Self {
        TrackedHttp { 
            five_tuple,
            match_data: MatchData::new(pkt_results),
        }
    }

    fn update(&mut self, 
              _pdu: L4Pdu, 
              _session_id: Option<usize>,
              _subscription: &Subscription<Self::Subscribed>) {}

    fn deliver_session_on_match(&mut self, session: Session, subscription: &Subscription<Self::Subscribed>) -> ConnState {
        if let SessionData::Http(http) = session.data {
            subscription.invoke(HttpTransaction {
                five_tuple: self.five_tuple,
                data: *http,
            });
        }
        ConnState::Remove // Parser may keep
    }

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
