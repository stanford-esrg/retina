use crate::conntrack::conn_id::FiveTuple;
use crate::conntrack::pdu::L4Pdu;
use crate::conntrack::ConnTracker;
use crate::filter::*;
use crate::memory::mbuf::Mbuf;
use crate::protocols::stream::{ConnData, ConnParser, Session};

// mod data; // SubscribedData

pub trait Subscribable {
    type Tracked: Trackable<Subscribed = Self>;
    type SubscribedData;

    /// Parsers needed by all filters *and* data types [TODOTR??]
    fn parsers() -> Vec<ConnParser>;

    /// TEMP - TODOTR move packet handling out of subscription
    /// And figure out how to not apply it every time...?
    fn process_packet(
        mbuf: Mbuf,
        subscription: &Subscription<Self>,
        conn_tracker: &mut ConnTracker<Self::Tracked>,
        actions: PacketActions
    ) where
        Self: Sized;
}

pub trait Trackable {
    type Subscribed: Subscribable<Tracked = Self>;

    /// Create a new struct for tracking connection data for user delivery
    fn new(five_tuple: FiveTuple) -> Self;

    /// When tracking, parsing, or buffering frames, 
    /// update tracked data with new PDU
    fn update(&mut self, 
              pdu: L4Pdu, 
              session_id: Option<usize>, 
              actions: &ActionData);
    
    /// \todo 
    /// Handle draining frames

    /// When a session has been parsed and has matched, deliver it.
    /// If Actions includes delivery, deliver the session.
    /// ConnData is provided to apply delivery filter.
    /// If Actions includes storing the session, store it. 
    fn deliver_session(&mut self, session: Session, 
                       subscription: &Subscription<Self::Subscribed>,
                       actions: &ActionData, conn_data: &ConnData);

    /// Indicate that a tracked and matched connection has terminated.
    /// If connection subscriptions are matched, they will be delivered.
    /// --- \TODO check the logic of actions on terminate. Make sure we can ascertain match.
    fn deliver_conn(&mut self, 
                    subscription: &Subscription<Self::Subscribed>,
                    actions: &ActionData, conn_data: &ConnData);
    
    /// Deliver tracked five tuple (always tracked)
    fn five_tuple(&self) -> FiveTuple;
}

pub struct Subscription<S>
where 
    S: Subscribable,
{
    packet_continue: PacketContFn,
    packet_filter: PacketFilterFn,
    conn_filter: ConnFilterFn,
    session_filter: SessionFilterFn,
    packet_deliver: PacketDeliverFn,
    conn_deliver: ConnDeliverFn<S::Tracked>,
    session_deliver: SessionDeliverFn<S::Tracked>,
    #[cfg(feature = "timing")]
    pub(crate) timers: Timers,
}

impl<S> Subscription<S>
where
    S: Subscribable
{
    pub fn new(factory: FilterFactory<S::Tracked>) -> Self {
        Subscription {
            packet_continue: factory.packet_continue,
            packet_filter: factory.packet_filter,
            conn_filter: factory.conn_filter,
            session_filter: factory.session_filter,
            packet_deliver: factory.packet_deliver,
            conn_deliver: factory.conn_deliver,
            session_deliver: factory.session_deliver,
            #[cfg(feature = "timing")]
            timers: Timers::new(),
        }        
    }

    // TODOTR: 
    // - This should be built based on what the hardware supports (and filter)
    // 
    // For subscriptions with one possible packet action (track or deliver):
    // - If packet layer can be entirely realized in hardware: 
    //   * This should be no-op that returns Track. 
    //     (HW would have already dropped packets). 
    // - Else: 
    //   * Is it possible that the HW did some work for us but not all of it? 
    //     Can we figure out what the HW would have already filtered out 
    //     in order to reduce the work here? 
    // 
    // If there are two packet actions, this gets trickier. 
    // - If HW can mark packets and filter can be realized in hardware,
    //   then it's the same as the above --
    //   a no-op that just translates the mark to PacketAction
    // - If no marking or no/incomplete HW filter, then optimize 
    //   as much as possible...

    /// Applied when packet is first received in software.
    pub fn continue_packet(&self, mbuf: &Mbuf) -> PacketActions {
        (self.packet_continue)(mbuf)
    }

    /// Invokes the software packet filter.
    pub fn filter_packet(&self, mbuf: &Mbuf) -> Actions {
        (self.packet_filter)(mbuf)
    }

    /// Invokes the end-to-end connection filter.
    pub fn filter_conn(&self, conn: &ConnData) -> Actions {
        (self.conn_filter)(conn)
    }

    /// Invokes the application-layer session filter. 
    pub fn filter_session(&self, session: &Session, conn: &ConnData) -> Actions {
        (self.session_filter)(session, conn)
    }

    /// Delivery functions, including delivery to the correct callback

    pub fn deliver_packet(&self, mbuf: &Mbuf) {
        (self.packet_deliver)(mbuf)
    }

    pub fn deliver_conn(&self, conn_data: &ConnData, tracked: &S::Tracked) {
        (self.conn_deliver)(conn_data, tracked)
    }

    pub fn deliver_session(&self, session: std::rc::Rc<Session>, conn_data: &ConnData, tracked: &S::Tracked) {
        (self.session_deliver)(session, conn_data, tracked)
    }
}
