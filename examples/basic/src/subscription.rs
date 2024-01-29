use retina_core::conntrack::conn_id::FiveTuple;
use retina_core::conntrack::pdu::{L4Context, L4Pdu};
use retina_core::conntrack::ConnTracker;
use retina_core::memory::mbuf::Mbuf;
use retina_core::protocols::stream::tls::{parser::TlsParser, Tls};
use retina_core::protocols::stream::{ConnParser, Session, SessionData, ConnData};
use retina_core::subscription::{Subscribable, Subscription, Trackable};
use retina_core::filter::actions::*;

use retina_filtergen::subscription;

pub enum SubscribedData {
    _Tls(TlsConnection)
}

#[derive(Debug)]
pub struct TlsConnection {
    pub five_tuple: FiveTuple,
    pub data: Tls,
    pub pkt_count: usize,
}

pub struct SubscribedWrapper;

impl Subscribable for SubscribedWrapper {
    type Tracked = TrackedWrapper;
    type SubscribedData = SubscribedData;
    fn parsers() -> Vec<ConnParser> {
        vec![ConnParser::Tls(TlsParser::default())]
    }

    /// TEMP - TODOTR move packet handling out of subscription
    fn process_packet(
        mbuf: Mbuf,
        subscription: &Subscription<Self>,
        conn_tracker: &mut ConnTracker<Self::Tracked>,
        actions: PacketActions
    ) {
        if actions.contains(Packet::Deliver) {
            // Only include if actually needed
            subscription.deliver_packet(&mbuf);
        }
        if actions.contains(Packet::Track) {
            if let Ok(ctxt) = L4Context::new(&mbuf) {
                conn_tracker.process(mbuf, ctxt, subscription);
            }
        }
    }
}

#[derive(Debug)]
pub struct TrackedWrapper {
    _five_tuple: FiveTuple,
    data: Option<Tls>,
    pkt_count: usize,
}

impl Trackable for TrackedWrapper {
    type Subscribed = SubscribedWrapper;

    fn new(five_tuple: FiveTuple) -> Self {
        Self { 
            _five_tuple: five_tuple, 
            pkt_count: 0,
            data: None,
        }
    }

    fn five_tuple(&self) -> FiveTuple {
        self._five_tuple
    }

    fn update(&mut self, 
              _pdu: L4Pdu,
              _session_id: Option<usize>,
              _actions: &ActionData) {
        self.pkt_count += 1;
    }

    fn deliver_session(&mut self, session: Session,
                       subscription: &Subscription<Self::Subscribed>,
                       actions: &ActionData, conn_data: &ConnData)
    {
        if actions.contains(ActionFlags::SessionDeliver) {
            subscription.deliver_session(&session, &conn_data, &self);
        }
        if actions.contains(ActionFlags::SessionTrack) {
            if let SessionData::Tls(tls) = session.data {
                self.data = Some(*tls);
            }
        }
    }

    fn deliver_conn(&mut self, 
                    subscription: &Subscription<Self::Subscribed>,
                    _actions: &ActionData, conn_data: &ConnData) {
        subscription.deliver_conn(conn_data, self);
    }
}

#[subscription("/home/trossman/retina/examples/basic/filter.toml")]
fn test_lib() {}