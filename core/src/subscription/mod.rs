//! Subscribable data types.
//!
//! A subscription is a request for a callback on a subset of network traffic specified by a filter.
//! Callback functions are implemented as a closure that takes a subscribable data type as the
//! parameter and immutably borrows values from the environment. Built-in subscribable types can
//! be customized within the framework to provide additional data to the callback if needed.

pub mod connection;
pub mod connection_frame;
// pub mod dns_transaction;
pub mod frame;
//pub mod http_transaction;
pub mod tls_handshake;
//pub mod zc_frame;
pub mod tls_connection;

// Re-export subscribable types for more convenient usage.
pub use self::connection::Connection;
pub use self::connection_frame::ConnectionFrame;
//pub use self::dns_transaction::DnsTransaction;
pub use self::frame::Frame;
//pub use self::http_transaction::HttpTransaction;
pub use self::tls_handshake::TlsHandshake;
//pub use self::zc_frame::ZcFrame;
pub use self::tls_connection::{TlsConnection, TlsConnectionSubscription};

use crate::conntrack::conn_id::FiveTuple;
use crate::conntrack::pdu::L4Pdu;
use crate::conntrack::ConnTracker;
use crate::conntrack::conn::conn_info::{ConnState};
use crate::filter::{ConnFilterFn, PacketFilterFn, SessionFilterFn};
use crate::filter::{FilterFactory, FilterResult, FilterResultData};
use crate::memory::mbuf::Mbuf;
use crate::protocols::stream::{ConnData, ConnParser, Session};

#[cfg(feature = "timing")]
use crate::timing::timer::Timers;

/// The abstraction level of the subscribable type.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    /// Suitable for analyzing individual packets or frames where connection-level semantics are
    /// unnecessary.
    Packet,
    /// Suitable for analyzing entire connections, whether as a single record or a stream.
    Connection,
    /// Suitable for analyzing session-level data, of which there may be multiple instances per
    /// connection.
    Session,
}

pub trait SubscribedData {}

/// Represents a generic subscribable type. All subscribable types must implement this trait.
pub trait Subscribable {
    type Tracked: Trackable<Subscribed = Self>;
    // Subscribed type returned to callback.
    type SubscribedData;

    /// Returns a list of protocol parsers required to parse the subscribable type.
    fn parsers() -> Vec<ConnParser>;

    /// Process a single incoming packet.
    fn process_packet(
        mbuf: Mbuf,
        subscription: &Subscription<Self>,
        conn_tracker: &mut ConnTracker<Self::Tracked>,
    ) where
        Self: Sized;
}

/// Tracks subscribable types throughout the duration of a connection.
pub trait Trackable {
    type Subscribed: Subscribable<Tracked = Self>;

    /// Create a new Trackable type to manage subscription data for the duration of the connection
    /// represented by `five_tuple`.
    fn new(five_tuple: FiveTuple, pkt_result: FilterResultData) -> Self;

    fn update(&mut self, 
              // Needed for connection and frame data
              pdu: L4Pdu, 
              // Needed for frame-level subscriptions - if filtering by session, 
              // only deliver packets associated with matched session (may have multiple per connection)
              session_id: Option<usize>, 
              subscription: &Subscription<Self::Subscribed>);

    // Needed for session data
    fn deliver_session_on_match(&mut self, session: Session, 
                                subscription: &Subscription<Self::Subscribed>) -> ConnState;

    /// Update tracked subscr iption data on connection termination.
    fn on_terminate(&mut self, subscription: &Subscription<Self::Subscribed>);
    
    fn filter_packet(&mut self, pkt_filter_result: FilterResultData);
    fn filter_conn(&mut self, conn: &ConnData, subscription:  &Subscription<Self::Subscribed>) -> FilterResult;
    fn filter_session(&mut self, session: &Session, subscription: &Subscription<Self::Subscribed>) -> bool;
}

/// A request for a callback on a subset of traffic specified by the filter.
#[doc(hidden)]
pub struct Subscription<'a, S>
where
    S: Subscribable,
{
    packet_filter: PacketFilterFn,
    conn_filter: ConnFilterFn,
    session_filter: SessionFilterFn,
    callbacks: Vec<Box<dyn Fn(S::SubscribedData) + 'a>>,
    #[cfg(feature = "timing")]
    pub(crate) timers: Timers,
}

impl<'a, S> Subscription<'a, S>
where
    S: Subscribable,
{
    /// Creates a new subscription from a filter and a callback.
    pub(crate) fn new(factory: FilterFactory, callbacks: Vec<Box<dyn Fn(S::SubscribedData) + 'a>>) -> Self {
        Subscription {
            packet_filter: factory.packet_filter,
            conn_filter: factory.conn_filter,
            session_filter: factory.session_filter,
            callbacks,
            #[cfg(feature = "timing")]
            timers: Timers::new(),
        }
    }

    /// Invokes the software packet filter.
    pub(crate) fn filter_packet(&self, mbuf: &Mbuf) -> FilterResultData {
        (self.packet_filter)(mbuf)
    }

    /// Invokes the connection filter.
    pub(crate) fn filter_conn(&self, pkt_result: &FilterResultData, conn: &ConnData) -> FilterResultData {
        (self.conn_filter)(pkt_result, conn)
    }

    /// Invokes the application-layer session filter. The `idx` parameter is the numerical ID of the
    /// session.
    pub(crate) fn filter_session(&self, session: &Session, conn_result: &FilterResultData) -> FilterResultData {
        (self.session_filter)(session, conn_result)
    }

    /// Invoke the callback on `S`.
    pub(crate) fn invoke(&self, obj: S::SubscribedData) {
        tsc_start!(t0);
        (self.callbacks[0])(obj);
        tsc_record!(self.timers, "callback", t0);
    }

    /// Invoke the `idx`th callback on `S`.
    pub(crate) fn _invoke_idx(&self, obj: S::SubscribedData, idx: usize) {
        tsc_start!(t0);
        (self.callbacks[idx])(obj);
        tsc_record!(self.timers, "callback", t0);
    }
}


pub struct MatchData {
    pkt_filter_result: FilterResultData,
    conn_filter_result: Option<FilterResultData>,
    // Bit vector: filters matched so far
    pub matched_terminal: u32,
    pub matched_nonterminal: u32,
}

impl MatchData {
    pub fn new(pkt_filter_result: FilterResultData) -> Self {
        let term_matches = pkt_filter_result.terminal_matches;
        let nonterm_matches = pkt_filter_result.nonterminal_matches;
        Self {
            pkt_filter_result, 
            conn_filter_result: None,
            matched_terminal: term_matches,
            matched_nonterminal: nonterm_matches,
        }
    }

    pub fn filter_packet(&mut self, pkt_filter_result: FilterResultData) {
        self.pkt_filter_result = pkt_filter_result;
        self.matched_terminal = self.pkt_filter_result.terminal_matches;
        self.matched_nonterminal = self.pkt_filter_result.nonterminal_matches;
    }

    pub fn filter_conn<S: Subscribable>(&mut self, conn: &ConnData, subscription: &Subscription<S>) -> FilterResult {

        let result = subscription.filter_conn(&self.pkt_filter_result, conn);
        // If any packet filters already terminally matched, maintain them
        self.matched_terminal |= result.terminal_matches;
        self.matched_nonterminal = result.nonterminal_matches;
        self.conn_filter_result = Some(result);
        
        if self.matched_terminal != 0 {
            return FilterResult::MatchTerminal(0);
        } else if self.matched_nonterminal != 0 {
            return FilterResult::MatchNonTerminal(0);
        }
        FilterResult::NoMatch
    }

    pub fn filter_session<S: Subscribable>(&mut self, session: &Session, subscription: &Subscription<S>) -> bool {

        let result = match &self.conn_filter_result {
            Some(result_data) => { 
                subscription.filter_session(session, &result_data) 
            },
            None => { 
                subscription.filter_session(session, &self.pkt_filter_result)
            },
        };
        self.matched_terminal |= result.terminal_matches;
        self.matched_nonterminal = result.nonterminal_matches;
        return self.matched_terminal != 0;
    }

    #[inline]
    pub fn matched_term_by_idx(&self, idx: usize) -> bool {
        self.matched_terminal & (0b1 << idx) != 0
    }

    #[inline]
    pub fn matching_by_idx(&self, idx: usize) -> bool {
        (self.matched_terminal | self.matched_nonterminal) & (0b1 << idx) != 0
    }

    #[inline]
    pub fn matched_nonterm_by_idx(&self, idx: usize) -> bool {
        self.matched_nonterminal & (0b1 << idx) != 0
    }

}