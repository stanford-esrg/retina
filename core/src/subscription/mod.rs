use crate::conntrack::pdu::{L4Context, L4Pdu};
use crate::conntrack::ConnTracker;
use crate::filter::*;
use crate::lcore::CoreId;
use crate::memory::mbuf::Mbuf;
use crate::protocols::packet::tcp::TCP_PROTOCOL;
use crate::protocols::packet::udp::UDP_PROTOCOL;
use crate::protocols::stream::{ConnData, ParserRegistry, Session};
use crate::stats::{StatExt, TCP_BYTE, TCP_PKT, UDP_BYTE, UDP_PKT};

#[cfg(feature = "timing")]
use crate::timing::timer::Timers;

pub trait Subscribable {
    type Tracked: Trackable<Subscribed = Self>;
}

pub trait Trackable {
    type Subscribed: Subscribable<Tracked = Self>;

    /// Create a new struct for tracking connection data for user delivery
    fn new(first_pkt: &L4Pdu, core_id: CoreId) -> Self;

    /// When tracking, parsing, or buffering frames,
    /// update tracked data with new PDU
    fn update(&mut self, pdu: &L4Pdu, reassembled: bool);

    /// Get a reference to all sessions that matched filter(s) in connection
    fn sessions(&self) -> &Vec<Session>;

    /// Store a session that matched
    fn track_session(&mut self, session: Session);

    /// Store packets for (possible) future delivery
    fn buffer_packet(&mut self, pdu: &L4Pdu, actions: &Actions, reassembled: bool);

    /// Get reference to stored packets (those buffered for delivery)
    fn packets(&self) -> &Vec<Mbuf>;

    /// Drain data from all types that require storing packets
    /// Can help free mbufs for future use
    fn drain_tracked_packets(&mut self);

    /// Drain data from packets cached for future potential delivery
    /// Used after these packets have been delivered or when associated
    /// subscription fails to match
    fn drain_cached_packets(&mut self);

    /// Return the core ID that this tracked conn. is on
    fn core_id(&self) -> &CoreId;

    /// Parsers needed by all datatypes
    /// Parsers needed by filter are generated on program startup
    fn parsers() -> ParserRegistry;

    /// Clear all internal data
    fn clear(&mut self);
}

pub struct Subscription<S>
where
    S: Subscribable,
{
    packet_continue: PacketContFn,
    packet_filter: PacketFilterFn<S::Tracked>,
    proto_filter: ProtoFilterFn<S::Tracked>,
    session_filter: SessionFilterFn<S::Tracked>,
    packet_deliver: PacketDeliverFn<S::Tracked>,
    conn_deliver: ConnDeliverFn<S::Tracked>,
    #[cfg(feature = "timing")]
    pub(crate) timers: Timers,
}

impl<S> Subscription<S>
where
    S: Subscribable,
{
    pub fn new(factory: FilterFactory<S::Tracked>) -> Self {
        Subscription {
            packet_continue: factory.packet_continue,
            packet_filter: factory.packet_filter,
            proto_filter: factory.proto_filter,
            session_filter: factory.session_filter,
            packet_deliver: factory.packet_deliver,
            conn_deliver: factory.conn_deliver,
            #[cfg(feature = "timing")]
            timers: Timers::new(),
        }
    }

    pub fn process_packet(
        &self,
        mbuf: Mbuf,
        conn_tracker: &mut ConnTracker<S::Tracked>,
        actions: Actions,
    ) {
        if actions.data.intersects(ActionData::PacketContinue) {
            if let Ok(ctxt) = L4Context::new(&mbuf) {
                match ctxt.proto {
                    TCP_PROTOCOL => {
                        TCP_PKT.inc();
                        TCP_BYTE.inc_by(mbuf.data_len() as u64);
                    }
                    UDP_PROTOCOL => {
                        UDP_PKT.inc();
                        UDP_BYTE.inc_by(mbuf.data_len() as u64);
                    }
                    _ => {}
                }
                conn_tracker.process(mbuf, ctxt, self);
            }
        }
    }

    // TODO: packet continue filter should ideally be built at
    // compile-time based on what the NIC supports (what has
    // already been filtered out in HW).
    // Ideally, NIC would `mark` mbufs as `deliver` and/or `continue`.
    /// Invokes the software packet filter.
    /// Used for each packet to determine
    /// forwarding to conn. tracker.
    pub fn continue_packet(&self, mbuf: &Mbuf, core_id: &CoreId) -> Actions {
        (self.packet_continue)(mbuf, core_id)
    }

    /// Invokes the five-tuple filter.
    /// Applied to the first packet in the connection.
    pub fn filter_packet(&self, mbuf: &Mbuf, tracked: &S::Tracked) -> Actions {
        (self.packet_filter)(mbuf, tracked)
    }

    /// Invokes the end-to-end protocol filter.
    /// Applied once a parser identifies the application-layer protocol.
    pub fn filter_protocol(&self, conn: &ConnData, tracked: &S::Tracked) -> Actions {
        (self.proto_filter)(conn, tracked)
    }

    /// Invokes the application-layer session filter.
    /// Delivers sessions to callbacks if applicable.
    pub fn filter_session(
        &self,
        session: &Session,
        conn: &ConnData,
        tracked: &S::Tracked,
    ) -> Actions {
        (self.session_filter)(session, conn, tracked)
    }

    /// Delivery functions, including delivery to the correct callback
    pub fn deliver_packet(&self, mbuf: &Mbuf, conn_data: &ConnData, tracked: &S::Tracked) {
        (self.packet_deliver)(mbuf, conn_data, tracked)
    }

    pub fn deliver_conn(&self, conn_data: &ConnData, tracked: &S::Tracked) {
        (self.conn_deliver)(conn_data, tracked)
    }
}
