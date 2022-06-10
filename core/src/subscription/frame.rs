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
use crate::filter::FilterResult;
use crate::memory::mbuf::Mbuf;
use crate::protocols::stream::{ConnParser, Session};
use crate::subscription::{Level, Subscribable, Subscription, Trackable};

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

    fn level() -> Level {
        Level::Packet
    }

    fn parsers() -> Vec<ConnParser> {
        vec![]
    }

    fn process_packet(
        mbuf: Mbuf,
        subscription: &Subscription<Self>,
        conn_tracker: &mut ConnTracker<Self::Tracked>,
    ) {
        match subscription.filter_packet(&mbuf) {
            FilterResult::MatchTerminal(_idx) => {
                let frame = Frame::from_mbuf(&mbuf);
                subscription.invoke(frame);
            }
            FilterResult::MatchNonTerminal(idx) => {
                if let Ok(ctxt) = L4Context::new(&mbuf, idx) {
                    conn_tracker.process(mbuf, ctxt, subscription);
                }
            }
            FilterResult::NoMatch => drop(mbuf),
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
    // Buffers packets not associated with parsed sessions. (e.g., control packets, malformed,
    // etc.). misc_buf: Vec<Mbuf>,
}

impl Trackable for TrackedFrame {
    type Subscribed = Frame;

    fn new(_five_tuple: FiveTuple) -> Self {
        TrackedFrame {
            session_buf: HashMap::new(),
            // misc_buf: vec![],
        }
    }

    fn pre_match(&mut self, pdu: L4Pdu, session_id: Option<usize>) {
        if let Some(session_id) = session_id {
            self.session_buf
                .entry(session_id)
                .or_insert_with(Vec::new)
                .push(pdu.mbuf_own());
        } else {
            drop(pdu);
            // self.misc_buf.push(pdu.mbuf_own());
        }
    }

    fn on_match(&mut self, session: Session, subscription: &Subscription<Self::Subscribed>) {
        if let Some(session) = self.session_buf.remove(&session.id) {
            session.into_iter().for_each(|mbuf| {
                let frame = Frame::from_mbuf(&mbuf);
                subscription.invoke(frame);
            });
        }
    }

    fn post_match(&mut self, pdu: L4Pdu, subscription: &Subscription<Self::Subscribed>) {
        let frame = Frame::from_mbuf(&pdu.mbuf_own());
        subscription.invoke(frame);
    }

    fn on_terminate(&mut self, _subscription: &Subscription<Self::Subscribed>) {}
}
