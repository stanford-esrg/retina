//! Subscribable data types.
//!
//! A subscription is a request for a callback on a subset of network traffic specified by a filter.
//! Callback functions are implemented as a closure that takes a subscribable data type as the
//! parameter and immutably borrows values from the environment. Built-in subscribable types can
//! be customized within the framework to provide additional data to the callback if needed.

pub mod connection;
pub mod connection_frame;
pub mod dns_transaction;
pub mod frame;
pub mod http_transaction;
pub mod tls_handshake;
pub mod zc_frame;
pub mod tls_connection;
pub mod custom; 

pub use self::custom::custom_data::{SubscribableWrapper, Subscribed};

// Re-export subscribable types for more convenient usage.
pub use self::connection::Connection;
pub use self::connection_frame::ConnectionFrame;
pub use self::dns_transaction::DnsTransaction;
pub use self::frame::Frame;
pub use self::http_transaction::HttpTransaction;
pub use self::tls_handshake::TlsHandshake;
pub use self::zc_frame::ZcFrame;
pub use self::tls_connection::TlsConnection;

use crate::conntrack::conn_id::FiveTuple;
use crate::conntrack::pdu::L4Pdu;
use crate::conntrack::ConnTracker;
use crate::conntrack::conn::conn_info::ConnState;
use crate::filter::{ConnFilterFn, PacketFilterFn, SessionFilterFn};
use crate::filter::{FilterFactory, FilterResult, FilterResultData};
use crate::memory::mbuf::Mbuf;
use crate::protocols::stream::{ConnData, ConnParser, Session};
use retina_subscriptiongen::num_subscriptions;

#[cfg(feature = "timing")]
use crate::timing::timer::Timers;

/// This is filled in by user configuration.
#[num_subscriptions]
pub const NUM_SUBSCRIPTIONS: usize = 1;

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
    #[allow(dead_code)]
    pub(crate) fn invoke_idx(&self, obj: S::SubscribedData, idx: usize) {
        tsc_start!(t0);
        (self.callbacks[idx])(obj);
        tsc_record!(self.timers, "callback", t0);
    }
}


pub struct MatchData {
    pkt_filter_result: FilterResultData,
    conn_filter_result: Option<FilterResultData>,
    conn_term_matched: u32,
    conn_nonterm_matched: u32,
    session_term_matched: u32,
}

impl MatchData {
    pub fn new(pkt_filter_result: FilterResultData) -> Self {
        Self {
            pkt_filter_result, 
            conn_filter_result: None,
            conn_term_matched: 0,
            conn_nonterm_matched: 0,
            session_term_matched: 0
        }
    }

    pub fn filter_packet(&mut self, pkt_filter_result: FilterResultData) {
        self.pkt_filter_result = pkt_filter_result;
    }

    pub fn filter_conn<S: Subscribable>(&mut self, conn: &ConnData, subscription: &Subscription<S>) -> FilterResult {
        let result = subscription.filter_conn(&self.pkt_filter_result, conn);
        self.conn_nonterm_matched = result.nonterminal_matches;
        self.conn_term_matched = result.terminal_matches;
        self.conn_filter_result = Some(result);
        return {
            if self.terminal_matches() != 0 {
                FilterResult::MatchTerminal(0)
            } else if self.nonterminal_matches() != 0 {
                FilterResult::MatchNonTerminal(0)
            } else {
                FilterResult::NoMatch
            }
        }
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
        self.session_term_matched = result.terminal_matches;
        return self.terminal_matches() != 0;
    }

    // TODO: API to clear `session match` after session delivery if subscription isn't cnxn-level?

    #[inline]
    fn terminal_matches(&self) -> u32 {
        self.session_term_matched | self.conn_term_matched | self.pkt_filter_result.terminal_matches
    }

    #[inline]
    fn nonterminal_matches(&self) -> u32 {
        self.conn_nonterm_matched | self.pkt_filter_result.nonterminal_matches
    }

    #[inline]
    pub fn matched_term_by_idx(&self, idx: usize) -> bool {
        self.terminal_matches() & (0b1 << idx) != 0
    }

    #[inline]
    pub fn matching_by_idx(&self, idx: usize) -> bool {
        (self.nonterminal_matches() | self.terminal_matches()) & (0b1 << idx) != 0
    }

    #[inline]
    pub fn matching_by_bitmask(&self, bitmask: u32) -> bool {
        (self.nonterminal_matches() | self.terminal_matches()) & bitmask != 0
    }

    #[inline]
    pub fn matched_nonterm_by_idx(&self, idx: usize) -> bool {
        self.nonterminal_matches() & (0b1 << idx) != 0
    }

}