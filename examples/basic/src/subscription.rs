use retina_core::conntrack::conn_id::FiveTuple;
use retina_core::conntrack::pdu::{L4Context, L4Pdu};
use retina_core::conntrack::ConnTracker;
use retina_core::memory::mbuf::Mbuf;
use retina_core::protocols::stream::tls::{parser::TlsParser, Tls};
use retina_core::protocols::stream::{ConnParser, Session, SessionData, ConnData};
use retina_core::subscription::{Subscribable, Subscription, Trackable};
use retina_core::filter::{ActionFlags, ActionData};

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
    ) {
        // \TRDEBUG this is being called
        let mut actions = subscription.filter_packet(&mbuf);
        if actions.data.contains(ActionFlags::FrameDeliver) {
            subscription.deliver_packet(&mbuf);
            actions.data.unset(ActionFlags::FrameDeliver);
        }
        if !actions.drop() {
            // \TRDEBUG This is also being called
            if let Ok(ctxt) = L4Context::new(&mbuf) {
                conn_tracker.process(mbuf, ctxt, subscription, actions);
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

pub(super) fn filter() -> retina_core::filter::FilterFactory<TrackedWrapper> {
    #[inline]
    fn packet_filter(mbuf: &retina_core::Mbuf) -> retina_core::filter::actions::Actions {
        let mut actions = retina_core::filter::actions::Actions::new();
        if let Ok(ethernet)
            = &retina_core::protocols::packet::Packet::parse_to::<
                retina_core::protocols::packet::ethernet::Ethernet,
            >(mbuf) {
            if let Ok(ipv4)
                = &retina_core::protocols::packet::Packet::parse_to::<
                    retina_core::protocols::packet::ipv4::Ipv4,
                >(ethernet) {
                if let Ok(_tcp)
                    = &retina_core::protocols::packet::Packet::parse_to::<
                        retina_core::protocols::packet::tcp::Tcp,
                    >(ipv4) {
                    // IPV4 & TCP MATCH - non-terminal match [doing tracked conn here]
                    actions.data.set(retina_core::filter::actions::ActionFlags::ConnDataTrack |
                                     retina_core::filter::actions::ActionFlags::ConnParse     |
                                     retina_core::filter::actions::ActionFlags::ConnFilter);
                 
                 // for tcp filter [separate test]
                 //   actions.data.set(retina_core::filter::actions::ActionFlags::ConnDataTrack);
                 //   actions.terminal_actions.set(retina_core::filter::actions::ActionFlags::ConnDataTrack);
                    
                }
            }
        }
        actions
    }

    #[inline]
    fn connection_filter(
        conn: &retina_core::protocols::stream::ConnData,
    ) -> retina_core::filter::actions::Actions {
        let mut actions = retina_core::filter::actions::Actions::new();
        if matches!(conn.five_tuple.orig, std::net::SocketAddr::V4(_)) {
            if match conn.service() {
                retina_core::protocols::stream::ConnParser::Tls { .. } => true,
                _ => false,
            } {
                // Ipv4 and TLS match
                actions.data.set(retina_core::filter::actions::ActionFlags::SessionParse | 
                                 retina_core::filter::actions::ActionFlags::ConnDataTrack |
                                 retina_core::filter::actions::ActionFlags::SessionTrack);
                actions.terminal_actions.set(retina_core::filter::actions::ActionFlags::SessionParse);
            }
        }
        actions
    }

    #[inline]
    fn session_filter(
        _session: &retina_core::protocols::stream::Session,
        _conn_data: &retina_core::protocols::stream::ConnData,
    ) -> retina_core::filter::actions::Actions {
        // No new info here
        retina_core::filter::actions::Actions::new()
    }

    fn packet_deliver(mbuf: &Mbuf) {
        println!("Pkt!");
    }

    fn conn_deliver(_conn_data: &ConnData, tracked: &TrackedWrapper) {
        println!("Conn! {:?}", tracked._five_tuple);
    }

    fn session_deliver(session: &Session, _conn_data: &ConnData, _tracked: &TrackedWrapper) {
        println!("Session!");
    }


    retina_core::filter::FilterFactory::new(
        "tls and ipv4",
        "tls",
        packet_filter,
        connection_filter,
        session_filter,
        packet_deliver, 
        conn_deliver,
        session_deliver,
    )
}