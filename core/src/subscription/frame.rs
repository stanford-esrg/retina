//! Ethernet frames.
//!
//! This is a packet-level subscription that delivers raw Ethernet frames in the order of arrival.
//!
//! ## Example
//! Prints IPv4 packets with a TTL greater than 64:
//! ```
//! #[filter("ipv4.time_to_live > 64")]
//! fn main() {
//!     let config = default_config();
//!     let cb = |frame: Frame| {
//!         println!("{:?}", frame.data);
//!     };
//!     let mut runtime = Runtime::new(config, filter, cb).unwrap();
//!     runtime.run();
//! }
//! ```
//!
//! ## Remarks
//! The `Frame` type is most suited for packet-specific analysis with filters that do not require
//! connection tracking or stream-level protocol parsing. While all types of filters are technically
//! allowed, some may introduce subtle behaviors.
//!
//! For example, take the filter `tcp.port = 80 or http`. Packet-level filters take precedence in
//! Retina, meaning that if a packet satisfies the filter, the callback will immediately be invoked.
//! In this example, Retina will deliver all TCP packets where the source or destination port is 80,
//! as well as packets associated with HTTP request/response messages (not including control
//! packets) in connections not on port 80. For HTTP connections on port 80, Retina will deliver all
//! packets in the connection (including control packets) by virtue of satisfying the `tcp.port =
//! 80` predicate.
//!
//! To subscribe to all packets in the connection by default (with connection-level semantics), use
//! [`ConnectionFrame`](crate::subscription::connection_frame::ConnectionFrame) instead.

use crate::conntrack::conn_id::FiveTuple;
use crate::conntrack::pdu::{L4Context, L4Pdu};
use crate::conntrack::ConnTracker;
use crate::conntrack::conn::conn_info::ConnState;
use crate::filter::{FilterResult, FilterResultData};
use crate::memory::mbuf::Mbuf;
use crate::protocols::stream::{ConnParser, Session, ConnData};
use crate::subscription::{Subscribable, Subscription, Trackable, MatchData};

use std::collections::HashMap;

/// An Ethernet Frame.
///
/// ## Remarks
/// This subscribable type is equivalent to an owned packet buffer. Internally, packet data remains
/// in memory pool-allocated DPDK message buffers for as long as possible, before it is copied into
/// a heap buffer to transfer ownership to the callback on a filter match. The DPDK message buffers
/// are then freed back to the memory pool.
#[derive(Debug, Clone)]
pub struct Frame {
    pub data: Vec<u8>,
}

impl Frame {
    pub(crate) fn from_mbuf(mbuf: &Mbuf) -> Self {
        Frame {
            data: mbuf.data().to_vec(),
        }
    }
}

impl Subscribable for Frame {
    type Tracked = TrackedFrame;
    type SubscribedData = Self;

    fn parsers() -> Vec<ConnParser> {
        vec![]
    }

    fn process_packet(
        mbuf: Mbuf,
        subscription: &Subscription<Self>,
        conn_tracker: &mut ConnTracker<Self::Tracked>,
    ) {
        let result = subscription.filter_packet(&mbuf);
        if result.terminal_matches != 0 {
            let frame = Frame::from_mbuf(&mbuf);
            subscription.invoke(frame);
        } else if result.nonterminal_matches != 0 {
            if let Ok(ctxt) = L4Context::new(&mbuf) {
                conn_tracker.process(mbuf, ctxt, subscription, result);
            }
        } else {
            drop(mbuf);
        }
    }
}

/// Buffers packets associated with parsed sessions throughout the duration of the connection.
///
/// ## Note
/// Internal connection state is an associated type of a `pub` trait, and therefore must also be
/// public. Documentation is hidden by default to avoid confusing users.
#[doc(hidden)]
pub struct TrackedFrame {
    session_buf: HashMap<usize, Vec<Mbuf>>,
    match_data: MatchData,
    // Buffers packets not associated with parsed sessions. (e.g., control packets, malformed,
    // etc.). misc_buf: Vec<Mbuf>,
}

impl Trackable for TrackedFrame {
    type Subscribed = Frame;

    fn new(_five_tuple: FiveTuple, pkt_results: FilterResultData) -> Self {
        TrackedFrame {
            session_buf: HashMap::new(),
            match_data: MatchData::new(pkt_results),
        }
    }

    fn update(&mut self, 
              // Needed for connection and frame data
              pdu: L4Pdu, 
              // Needed for frame-level subscriptions - if filtering by session, 
              // only deliver packets associated with matched session (may have multiple per connection)
              session_id: Option<usize>, 
              _subscription: &Subscription<Self::Subscribed>)
    {
        // `post_match` calls to `update` will not be called for `Level::Packet`
        // subscriptions -- `post_match` is only used for `ConnState::Tracking`, 
        // which only happens in `Level::Connection`.
        
        // All that needs to be considered here is the `pre_match` case. 
        if let Some(session_id) = session_id {
            // TODOTR/NOTETR: optimize when there's no session-level filtering needed!
            self.session_buf
                .entry(session_id)
                .or_insert_with(Vec::new)
                .push(pdu.mbuf_own());
        } else {
            drop(pdu);
        }
    }

    // Session-level frames are delivered on session match
    fn deliver_session_on_match(&mut self, session: Session, 
                                subscription: &Subscription<Self::Subscribed>) -> ConnState
    {
        if let Some(session) = self.session_buf.remove(&session.id) {
            session.into_iter().for_each(|mbuf| {
                let frame = Frame::from_mbuf(&mbuf);
                subscription.invoke(frame);
            });
        }
        return ConnState::Remove;
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
