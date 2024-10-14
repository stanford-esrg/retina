// Consume_PDU [invoked on first pkt and UDP [in update], + via reassembled TCP]
// Update [invoked on non-first pkt]
// Must now store actions
// Terminate handler
// Probe, parse, etc.

use crate::conntrack::pdu::L4Pdu;
use crate::filter::Actions;
use crate::lcore::CoreId;
use crate::protocols::packet::tcp::TCP_PROTOCOL;
use crate::protocols::stream::{
    ConnData, ParseResult, ParserRegistry, ProbeRegistryResult, SessionState,
};
use crate::subscription::{Subscription, Trackable};
use crate::FiveTuple;

#[derive(Debug)]
pub(crate) struct ConnInfo<T>
where
    T: Trackable,
{
    /// Actions to perform (connection state)
    pub(crate) actions: Actions,
    /// Connection data (for filtering)
    pub(crate) cdata: ConnData,
    /// Subscription data (for delivering)
    pub(crate) sdata: T,
}

impl<T> ConnInfo<T>
where
    T: Trackable,
{
    pub(super) fn new(pdu: &L4Pdu, core_id: CoreId) -> Self {
        let five_tuple = FiveTuple::from_ctxt(pdu.ctxt);
        ConnInfo {
            actions: Actions::new(),
            cdata: ConnData::new(five_tuple),
            sdata: T::new(pdu, core_id),
        }
    }

    pub(crate) fn filter_first_packet(
        &mut self,
        pdu: &L4Pdu,
        subscription: &Subscription<T::Subscribed>,
    ) {
        assert!(self.actions.drop());
        let pkt_actions = subscription.filter_packet(pdu.mbuf_ref(), &self.sdata);
        self.actions = pkt_actions;
    }

    pub(crate) fn consume_pdu(
        &mut self,
        pdu: L4Pdu,
        subscription: &Subscription<T::Subscribed>,
        registry: &ParserRegistry,
    ) {
        if self.actions.drop() {
            drop(pdu);
            return;
        }

        if self.actions.parse_any() {
            self.handle_parse(&pdu, subscription, registry);
        }

        // Post-reassembly `update`
        if self.actions.update_pdu_reassembled() && pdu.ctxt.proto == TCP_PROTOCOL {
            // Forward PDU to any subscriptions that require
            // tracking ongoing connection data post-reassembly
            self.sdata.update(&pdu, true);
        }
        if self.actions.packet_deliver() {
            // Delivering all remaining packets in connection
            subscription.deliver_packet(pdu.mbuf_ref(), &self.cdata, &self.sdata);
        }
        if self.actions.buffer_frame() {
            // Track frame for (potential) future delivery
            self.sdata.track_packet(pdu.mbuf_own());
        }
    }

    fn handle_parse(
        &mut self,
        pdu: &L4Pdu,
        subscription: &Subscription<T::Subscribed>,
        registry: &ParserRegistry,
    ) {
        // In probing stage: application-layer protocol unknown
        if self.actions.session_probe() {
            self.on_probe(pdu, subscription, registry);
        }

        // Parsing ongoing: application-layer protocol known
        if self.actions.session_parse() {
            self.on_parse(pdu, subscription);
        }
    }

    fn on_probe(
        &mut self,
        pdu: &L4Pdu,
        subscription: &Subscription<T::Subscribed>,
        registry: &ParserRegistry,
    ) {
        match registry.probe_all(pdu) {
            ProbeRegistryResult::Some(conn_parser) => {
                // Application-layer protocol known
                self.cdata.conn_parser = conn_parser;
                self.done_probe(subscription);
            }
            ProbeRegistryResult::None => {
                // All relevant parsers have failed to match
                // Handle connection state change
                self.done_probe(subscription);
            }
            ProbeRegistryResult::Unsure => { /* Continue */ }
        }
    }

    fn done_probe(&mut self, subscription: &Subscription<T::Subscribed>) {
        #[cfg(debug_assertions)]
        {
            if !self.actions.apply_proto_filter() {
                assert!(self.actions.drop() || !self.actions.terminal_actions.is_none());
            }
        }
        if self.actions.apply_proto_filter() {
            let actions = subscription.filter_protocol(&self.cdata, &self.sdata);
            self.clear_stale_data(&actions);
            self.actions.update(&actions);
        }
        self.actions.session_done_probe();
    }

    fn on_parse(&mut self, pdu: &L4Pdu, subscription: &Subscription<T::Subscribed>) {
        match self.cdata.conn_parser.parse(pdu) {
            ParseResult::Done(id) => self.handle_session(subscription, id),
            ParseResult::None => self.session_done_parse(subscription),
            _ => {} //
        }
    }

    fn handle_session(&mut self, subscription: &Subscription<T::Subscribed>, id: usize) {
        if let Some(session) = self.cdata.conn_parser.remove_session(id) {
            // Check if session was matched (to be tracked) at protocol level
            // (e.g., "tls" filter), but ensure tracking only happens once
            let session_track = self.actions.session_track();
            if self.actions.apply_session_filter() {
                let actions = subscription.filter_session(&session, &self.cdata, &self.sdata);
                self.clear_stale_data(&actions);
                self.actions.update(&actions);
            }
            if session_track || self.actions.session_track() {
                self.sdata.track_session(session);
            }
        } else {
            log::error!("Done parsing but no session found");
        }
        self.session_done_parse(subscription);
    }

    fn session_done_parse(&mut self, subscription: &Subscription<T::Subscribed>) {
        match self.cdata.conn_parser.session_parsed_state() {
            SessionState::Probing => {
                // Re-apply the protocol filter to update actions
                self.actions.session_set_probe();
            }
            SessionState::Remove => {
                // Done parsing: we expect no more sessions for this connection.
                self.actions.session_clear_parse();
                // If the only remaining thing to do is deliver the connection --
                // i.e., no more `updates` are required -- then we can deliver now,
                // as no more session parsing is expected.
                if self.actions.conn_deliver_only() {
                    self.handle_terminate(subscription);
                    self.actions.clear();
                }
            }
            SessionState::Parsing => {
                // SessionFilter, Track, and Delivery will be terminal actions if needed.
            }
        }
    }

    pub(crate) fn handle_terminate(&mut self, subscription: &Subscription<T::Subscribed>) {
        // Session parsing is ongoing: drain any remaining sessions
        if self.actions.session_parse() {
            for session in self.cdata.conn_parser.drain_sessions() {
                let session_track = self.actions.session_track();
                if self.actions.apply_session_filter() {
                    let actions = subscription.filter_session(&session, &self.cdata, &self.sdata);
                    self.actions.update(&actions);
                }
                if session_track || self.actions.session_track() {
                    self.sdata.track_session(session);
                }
            }
        }

        if self.actions.connection_matched() {
            subscription.deliver_conn(&self.cdata, &self.sdata)
        }

        self.actions.clear();
    }

    // Helper used after filter updates
    pub(crate) fn clear_packets(&mut self) {
        self.sdata.drain_packets();
    }

    // Helper to be used after applying protocol or session filter
    pub(crate) fn clear_stale_data(&mut self, new_actions: &Actions) {
        if self.actions.buffer_frame() && !new_actions.buffer_frame() && !self.actions.drop() {
            // No longer need tracked packets; delete to save memory
            // Don't clear if all connection data may be about to be dropped
            self.clear_packets();
            assert!(!new_actions.buffer_frame());
        }
        // Don't clear sessions, as SessionTrack is never
        // a terminal action at the protocol stage
        // (should be re-calculated per session).
    }

    // Helper to clear all data
    // Used for keeping empty UDP connections in the table until they age out
    pub(crate) fn clear(&mut self) {
        self.cdata.clear();
        self.sdata.clear();
    }
}
