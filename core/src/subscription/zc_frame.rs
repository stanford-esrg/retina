//! Zero-copy Ethernet frames.
//!
//! This is a packet-level subscription that delivers raw Ethernet frames in the order of arrival.
//! It has identical behavior to the [Frame](crate::subscription::frame::Frame) type, except is
//! zero-copy, meaning that callbacks are invoked on raw DPDK memory buffers instead of a
//! heap-allocated buffer. This is useful for performance sensitive applications that do not need to
//! store packet data. If ownership of the packet data is required, it is recommended to use
//! [Frame](crate::subscription::frame::Frame) instead.
//!
//! ## Warning
//! All `ZcFrame`s must be dropped (freed and returned to the memory pool) before the Retina runtime
//! is dropped.
//!
//! ## Example
//! Prints IPv4 packets with a TTL greater than 64:
//! ```
//! #[filter("ipv4.time_to_live > 64")]
//! fn main() {
//!     let config = default_config();
//!     let cb = |pkt: ZcFrame| {
//!         println!("{:?}", pkt.data());
//!         // implicit drop at end of scope
//!     };
//!     let mut runtime = Runtime::new(config, filter, cb).unwrap();
//!     runtime.run();
//!     // runtime dropped at end of scope
//! }
//! ```

use crate::conntrack::conn_id::FiveTuple;
use crate::conntrack::pdu::{L4Context, L4Pdu};
use crate::conntrack::ConnTracker;
use crate::filter::{FilterResult, FilterResultData};
use crate::memory::mbuf::Mbuf;
use crate::conntrack::conn::conn_info::ConnState;
use crate::protocols::stream::{ConnParser, Session, ConnData};
use crate::subscription::{Subscribable, Subscription, Trackable, MatchData};

use std::collections::HashMap;

/// A zero-copy Ethernet frame.
///
/// ## Remarks
/// This is a type alias of a DPDK message buffer. Retina allows subscriptions on raw DPDK memory
/// buffers with zero-copy (i.e., without copying into a heap-allocated buffer). This is useful for
/// performance sensitive applications that do not need to store packet data.
///
/// However, the callback does not obtain ownership of the packet. Therefore, all `ZcFrame`s must be
/// dropped before the runtime is dropped, or a segmentation fault may occur when the memory pools
/// are de-allocated. Storing `ZcFrame`s also reduces the number of available packet buffers for
/// incoming packets and can cause memory pool exhaustion.
///
/// It is recommended that `ZcFrame` be used for stateless packet analysis, and to use
/// [Frame](crate::subscription::Frame) instead if ownership of the packet is needed.
pub type ZcFrame = Mbuf;

impl Subscribable for ZcFrame {
    type Tracked = TrackedZcFrame;
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
            subscription.invoke(mbuf);
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
/// ## Note
/// Internal connection state is an associated type of a `pub` trait, and therefore must also be
/// public. Documentation is hidden by default to avoid confusing users.
#[doc(hidden)]
pub struct TrackedZcFrame {
    session_buf: HashMap<usize, Vec<Mbuf>>,
    match_data: MatchData,
}

impl Trackable for TrackedZcFrame {
    type Subscribed = ZcFrame;

    fn new(_five_tuple: FiveTuple, pkt_results: FilterResultData) -> Self {
        TrackedZcFrame {
            session_buf: HashMap::new(),
            // misc_buf: vec![],
            match_data: MatchData::new(pkt_results),
        }
    }

    fn deliver_session_on_match(&mut self, session: Session, 
                                subscription: &Subscription<Self::Subscribed>) -> ConnState {
        if let Some(session) = self.session_buf.remove(&session.id) {
            session.into_iter().for_each(|mbuf| {
                subscription.invoke(mbuf);
            });
        }
        // Following original Retina design
        ConnState::Remove
    }

    fn update(&mut self, 
        pdu: L4Pdu, 
        session_id: Option<usize>,
        subscription: &Subscription<Self::Subscribed>) {
        if self.match_data.matched_term_by_idx(0) {
            subscription.invoke(pdu.mbuf_own());
        } else {
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
