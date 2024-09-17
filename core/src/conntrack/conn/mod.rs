//! State management for connections.
//!
//! Tracks a TCP or UDP connection, performs stream reassembly, and (via ConnInfo)
//! manages protocol parser state throughout the duration of the connection.

pub mod conn_info;
pub mod tcp_conn;
pub mod udp_conn;

use self::conn_info::ConnInfo;
use self::tcp_conn::TcpConn;
use self::udp_conn::UdpConn;
use crate::conntrack::conn_id::FiveTuple;
use crate::conntrack::pdu::{L4Context, L4Pdu};
use crate::filter::Actions;
use crate::protocols::packet::tcp::{ACK, RST, SYN};
use crate::protocols::stream::ParserRegistry;
use crate::subscription::{Subscription, Trackable};
use crate::lcore::CoreId;

use anyhow::{bail, Result};
use std::time::Instant;

/// Tracks either a TCP or a UDP connection.
///
/// Performs light-weight stream reassembly for TCP connections and tracks UDP connections.
pub(crate) enum L4Conn {
    Tcp(TcpConn),
    Udp(UdpConn),
}

/// Connection state.
pub(crate) struct Conn<T>
where
    T: Trackable,
{
    /// Timestamp of the last observed packet in the connection.
    pub(crate) last_seen_ts: Instant,
    /// Amount of time (in milliseconds) before the connection should be expired for inactivity.
    pub(crate) inactivity_window: usize,
    /// Layer-4 connection tracking.
    pub(crate) l4conn: L4Conn,
    /// Connection tracking for filtering and parsing.
    pub(crate) info: ConnInfo<T>,
}

impl<T> Conn<T>
where
    T: Trackable,
{
    /// Creates a new TCP connection from `ctxt` with an initial inactivity window of
    /// `initial_timeout` and a maximum out-or-order tolerance of `max_ooo`. This means that there
    /// can be at most `max_ooo` packets buffered out of sequence before Retina chooses to discard
    /// the connection.
    pub(super) fn new_tcp(
        initial_timeout: usize,
        max_ooo: usize,
        pkt_actions: Actions,
        pdu: &L4Pdu,
        core_id: CoreId
    ) -> Result<Self> {
        let tcp_conn = if pdu.ctxt.flags & SYN != 0 && pdu.ctxt.flags & ACK == 0 && pdu.ctxt.flags & RST == 0 {
            TcpConn::new_on_syn(pdu.ctxt, max_ooo)
        } else {
            bail!("Not SYN")
        };
        Ok(Conn {
            last_seen_ts: Instant::now(),
            inactivity_window: initial_timeout,
            l4conn: L4Conn::Tcp(tcp_conn),
            info: ConnInfo::new(pdu, core_id, pkt_actions),
        })
    }

    /// Creates a new UDP connection from `ctxt` with an initial inactivity window of
    /// `initial_timeout`.
    #[allow(clippy::unnecessary_wraps)]
    pub(super) fn new_udp(
        initial_timeout: usize,
        pkt_actions: Actions,
        pdu: &L4Pdu,
        core_id: CoreId
    ) -> Result<Self> {
        let udp_conn = UdpConn;
        Ok(Conn {
            last_seen_ts: Instant::now(),
            inactivity_window: initial_timeout,
            l4conn: L4Conn::Udp(udp_conn),
            info: ConnInfo::new(pdu, core_id, pkt_actions),
        })
    }

    /// Updates a connection on the arrival of a new packet.
    pub(super) fn update(
        &mut self,
        pdu: L4Pdu,
        subscription: &Subscription<T::Subscribed>,
        registry: &ParserRegistry,
    ) {
        match &mut self.l4conn {
            L4Conn::Tcp(tcp_conn) => {
                tcp_conn.reassemble(pdu, &mut self.info, subscription, registry);
            }
            L4Conn::Udp(_udp_conn) => self.info.consume_pdu(pdu, subscription, registry),
        }
    }

    /// Returns the connection 5-tuple.
    pub(super) fn five_tuple(&self) -> FiveTuple {
        self.info.cdata.five_tuple
    }

    /// Returns `true` if the connection should be removed from the table.
    /// Note UDP connections are kept for a buffer period. UDP packets
    /// that pass the packet filter stage are assumed to represent an
    /// existing or new connection and are inserted into the connection
    /// table. Keeping UDP connections in "drop" state for a buffer
    /// period prevents dropped connections from being re-inserted.
    pub(super) fn remove(&self) -> bool {
        match &self.l4conn {
            L4Conn::Udp(_) => false,
            _ => self.info.actions.drop(),
        }
    }

    /// Returns `true` if PDUs for this connection should be dropped.
    pub(super) fn drop_pdu(&self) -> bool {
        self.info.actions.drop()
    }

    /// Returns `true` if the connection has been naturally terminated.
    pub(super) fn terminated(&self) -> bool {
        match &self.l4conn {
            L4Conn::Tcp(tcp_conn) => tcp_conn.is_terminated(),
            L4Conn::Udp(_udp_conn) => false,
        }
    }

    /// Returns the `true` if the packet represented by `ctxt` is in the direction of originator ->
    /// responder.
    pub(super) fn packet_dir(&self, ctxt: &L4Context) -> bool {
        self.five_tuple().orig == ctxt.src
    }

    /// Invokes connection termination tasks that are triggered when any of the following conditions
    /// occur:
    /// - the connection naturally terminates (e.g., FIN/RST)
    /// - the connection expires due to inactivity
    /// - the connection is drained at the end of the run
    pub(crate) fn terminate(&mut self, subscription: &Subscription<T::Subscribed>) {
        self.info.handle_terminate(subscription);
    }
}
