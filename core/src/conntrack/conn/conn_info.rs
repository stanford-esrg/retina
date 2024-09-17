// Consume_PDU [invoked on first pkt and UDP [in update], + via reassembled TCP]
// Update [invoked on non-first pkt]
// Must now store actions
// Terminate handler
// Probe, parse, etc.

use crate::lcore::CoreId;
use crate::FiveTuple;
use crate::conntrack::pdu::L4Pdu;
use crate::filter::Actions;
use crate::protocols::stream::{
    ConnData, ParseResult, ParserRegistry, ProbeRegistryResult, SessionState,
};
use crate::subscription::{Subscription, Trackable};

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
    pub(super) fn new(pdu: &L4Pdu, core_id: CoreId,
                      pkt_actions: Actions) -> Self {
        let five_tuple = FiveTuple::from_ctxt(pdu.ctxt);
        ConnInfo {
            actions: pkt_actions,
            cdata: ConnData::new(five_tuple),
            sdata: T::new(pdu, core_id),
        }
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
        if self.actions.update_pdu(true) {
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
                self.handle_conn(subscription);
            }
            ProbeRegistryResult::None => {
                // All relevant parsers have failed to match
                // Handle connection state change
                self.handle_conn(subscription);
            }
            ProbeRegistryResult::Unsure => { /* Continue */ }
        }
    }

    fn handle_conn(&mut self, subscription: &Subscription<T::Subscribed>) {
        #[cfg(debug_assertions)]
        {
            if !self.actions.apply_proto_filter() {
                assert!(self.actions.drop() || !self.actions.terminal_actions.is_none());
            }
        }
        if self.actions.apply_proto_filter() {
            let actions = subscription.filter_protocol(&self.cdata, &self.sdata);
            self.actions.update(&actions);
        }
    }

    fn on_parse(&mut self, pdu: &L4Pdu, subscription: &Subscription<T::Subscribed>) {
        if let ParseResult::Done(id) = self.cdata.conn_parser.parse(pdu) {
            self.handle_session(subscription, id);
        }
    }

    fn handle_session(&mut self, subscription: &Subscription<T::Subscribed>, id: usize) {
        if let Some(session) = self.cdata.conn_parser.remove_session(id) {
            if self.actions.apply_session_filter() {
                let actions = subscription.filter_session(&session, &self.cdata, &self.sdata);
                if self.actions.buffer_frame() != actions.buffer_frame() && !actions.drop() {
                    // No longer need tracked packets; delete to save memory
                    self.sdata.drain_packets();
                }
                self.actions.update(&actions);
            }
            if self.actions.session_track() {
                self.sdata.track_session(session);
            }
        } else {
            log::error!("Done parsing but no session found");
        }

        match self.cdata.conn_parser.session_parsed_state() {
            SessionState::Probing => {
                self.actions.session_set_probe();
            }
            SessionState::Remove => {
                // Done parsing: we expect no more sessions for this connection.
                self.actions.session_clear_parse();
            }
            SessionState::Parsing => {
                // SessionFilter, Track, and Delivery will be terminal actions if needed.
            }
        }
    }

    pub fn handle_terminate(&mut self, subscription: &Subscription<T::Subscribed>) {
        // Session parsing is ongoing: drain any remaining sessions
        if self.actions.session_parse() {
            for session in self.cdata.conn_parser.drain_sessions() {
                if self.actions.apply_session_filter() {
                    let actions = subscription.filter_session(&session, &self.cdata, &self.sdata);
                    self.actions.update(&actions);
                }
                if self.actions.session_track() {
                    self.sdata.track_session(session);
                }
            }
        }

        if self.actions.connection_matched() {
            subscription.deliver_conn(&self.cdata, &self.sdata)
        }

        self.actions.clear();
    }
}
