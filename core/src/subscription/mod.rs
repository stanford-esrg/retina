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

// Re-export subscribable types for more convenient usage.
pub use self::connection::Connection;
pub use self::connection_frame::ConnectionFrame;
pub use self::dns_transaction::DnsTransaction;
pub use self::frame::Frame;
pub use self::http_transaction::HttpTransaction;
pub use self::tls_handshake::TlsHandshake;
pub use self::zc_frame::ZcFrame;

use crate::conntrack::conn_id::FiveTuple;
use crate::conntrack::pdu::L4Pdu;
use crate::conntrack::ConnTracker;
use crate::filter::{ConnFilterFn, PacketFilterFn, SessionFilterFn};
use crate::filter::{FilterFactory, FilterResult};
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

/// Represents a generic subscribable type. All subscribable types must implement this trait.
pub trait Subscribable {
    type Tracked: Trackable<Subscribed = Self>;

    /// Returns the subscription level.
    fn level() -> Level;

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
    fn new(five_tuple: FiveTuple) -> Self;

    /// Update tracked subscription data prior to a full filter match.
    fn pre_match(&mut self, pdu: L4Pdu, session_id: Option<usize>);

    /// Update tracked subscription data on a full filter match.
    fn on_match(&mut self, session: Session, subscription: &Subscription<Self::Subscribed>);

    /// Update tracked subscription data after a full filter match.
    fn post_match(&mut self, pdu: L4Pdu, subscription: &Subscription<Self::Subscribed>);

    /// Update tracked subscription data on connection termination.
    fn on_terminate(&mut self, subscription: &Subscription<Self::Subscribed>);
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
    callback: Box<dyn Fn(S) + 'a>,
    #[cfg(feature = "timing")]
    pub(crate) timers: Timers,
}

impl<'a, S> Subscription<'a, S>
where
    S: Subscribable,
{
    /// Creates a new subscription from a filter and a callback.
    pub(crate) fn new(factory: FilterFactory, cb: impl Fn(S) + 'a) -> Self {
        Subscription {
            packet_filter: factory.packet_filter,
            conn_filter: factory.conn_filter,
            session_filter: factory.session_filter,
            callback: Box::new(cb),
            #[cfg(feature = "timing")]
            timers: Timers::new(),
        }
    }

    /// Invokes the software packet filter.
    pub(crate) fn filter_packet(&self, mbuf: &Mbuf) -> FilterResult {
        (self.packet_filter)(mbuf)
    }

    /// Invokes the connection filter.
    pub(crate) fn filter_conn(&self, conn: &ConnData) -> FilterResult {
        (self.conn_filter)(conn)
    }

    /// Invokes the application-layer session filter. The `idx` parameter is the numerical ID of the
    /// session.
    pub(crate) fn filter_session(&self, session: &Session, idx: usize) -> bool {
        (self.session_filter)(session, idx)
    }

    /// Invoke the callback on `S`.
    pub(crate) fn invoke(&self, obj: S) {
        tsc_start!(t0);
        (self.callback)(obj);
        tsc_record!(self.timers, "callback", t0);
    }
}
