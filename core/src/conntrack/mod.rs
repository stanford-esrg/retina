//! Connection state management.
//!
//! Most of this module's functionality is maintained internally by Retina and is not meant to be
//! directly managed by users. However, it publicly exposes some useful connection identifiers for
//! convenience.

pub(crate) mod conn;
pub mod conn_id;
pub(crate) mod pdu;
mod timerwheel;

use self::conn::conn_info::ConnState;
use self::conn::{Conn, L4Conn};
use self::conn_id::ConnId;
use self::pdu::{L4Context, L4Pdu};
use self::timerwheel::TimerWheel;
use crate::config::ConnTrackConfig;
use crate::memory::mbuf::Mbuf;
use crate::protocols::packet::tcp::TCP_PROTOCOL;
use crate::protocols::packet::udp::UDP_PROTOCOL;
use crate::protocols::stream::ParserRegistry;
use crate::subscription::{Subscription, Trackable};

use std::cmp;
use std::time::Instant;

use anyhow::anyhow;
use hashlink::linked_hash_map::{LinkedHashMap, RawEntryMut};

/// Manages state for all TCP and UDP connections.
///
/// One `ConnTracker` is maintained per core. `ConnTracker` is not meant to be directly managed by
/// users, but can be configured at runtime with a maximum capacity, out-of-order tolerance,
/// different timeout values, and other options. See
/// [ConnTrackConfig](crate::config::ConnTrackConfig) for details.
pub struct ConnTracker<T>
where
    T: Trackable,
{
    /// Configuration
    config: TrackerConfig,
    /// Contains required protocol parsers for `T`.
    registry: ParserRegistry,
    /// Manages `ConnId` to `Conn<T>` mappings.
    table: LinkedHashMap<ConnId, Conn<T>>,
    /// Manages connection timeouts.
    timerwheel: TimerWheel,
}

impl<T> ConnTracker<T>
where
    T: Trackable,
{
    /// Creates a new `ConnTracker`.
    pub(crate) fn new(config: TrackerConfig, registry: ParserRegistry) -> Self {
        let table = LinkedHashMap::with_capacity(config.max_connections);
        let timerwheel = TimerWheel::new(
            cmp::max(config.tcp_inactivity_timeout, config.udp_inactivity_timeout),
            config.timeout_resolution,
        );
        ConnTracker {
            config,
            registry,
            table,
            timerwheel,
        }
    }

    /// Returns the number of entries in the table.
    #[inline]
    pub(crate) fn size(&self) -> usize {
        self.table.len()
    }

    /// Process a single incoming packet `mbuf` with layer-4 context `ctxt`.
    pub(crate) fn process(
        &mut self,
        mbuf: Mbuf,
        ctxt: L4Context,
        subscription: &Subscription<T::Subscribed>,
    ) {
        let conn_id = ConnId::new(ctxt.src, ctxt.dst, ctxt.proto);
        match self.table.raw_entry_mut().from_key(&conn_id) {
            RawEntryMut::Occupied(mut occupied) => {
                let conn = occupied.get_mut();
                let dir = conn.packet_dir(&ctxt);
                conn.last_seen_ts = Instant::now();
                conn.inactivity_window = match &conn.l4conn {
                    L4Conn::Tcp(_) => self.config.tcp_inactivity_timeout,
                    L4Conn::Udp(_) => self.config.udp_inactivity_timeout,
                };
                if conn.state() == ConnState::Remove {
                    log::error!("Conn in Remove state when occupied in table");
                }
                let pdu = L4Pdu::new(mbuf, ctxt, dir);
                conn.update(pdu, subscription, &self.registry);
                if conn.state() == ConnState::Remove {
                    occupied.remove();
                    return;
                }

                if conn.terminated() {
                    conn.terminate(subscription);
                    occupied.remove();
                }
            }
            RawEntryMut::Vacant(_) => {
                if self.size() < self.config.max_connections {
                    let conn = match ctxt.proto {
                        TCP_PROTOCOL => Conn::new_tcp(
                            ctxt,
                            self.config.tcp_establish_timeout,
                            self.config.max_out_of_order,
                        ),
                        UDP_PROTOCOL => Conn::new_udp(ctxt, self.config.udp_inactivity_timeout),
                        _ => Err(anyhow!("Invalid L4 Protocol")),
                    };
                    if let Ok(mut conn) = conn {
                        let pdu = L4Pdu::new(mbuf, ctxt, true);
                        conn.info.consume_pdu(pdu, subscription, &self.registry);
                        if conn.state() != ConnState::Remove {
                            self.timerwheel.insert(
                                &conn_id,
                                conn.last_seen_ts,
                                conn.inactivity_window,
                            );
                            self.table.insert(conn_id, conn);
                        }
                    }
                } else {
                    log::error!("Table full. Dropping packet.");
                }
            }
        }
    }

    /// Drains any remaining connections that satisfy the filter on runtime termination.
    pub(crate) fn drain(&mut self, subscription: &Subscription<T::Subscribed>) {
        log::info!("Draining Connection table");
        for (_, mut conn) in self.table.drain() {
            conn.terminate(subscription);
        }
    }

    /// Checks for and removes inactive connections.
    pub(crate) fn check_inactive(&mut self, subscription: &Subscription<T::Subscribed>) {
        self.timerwheel
            .check_inactive(&mut self.table, subscription);
    }
}

/// Configurable options for a `ConnTracker`.
#[derive(Debug)]
pub(crate) struct TrackerConfig {
    /// Maximum number of connections that can be tracked per-core.
    pub(super) max_connections: usize,
    /// Maximum number of out-of-order packets allowed per TCP connection.
    pub(super) max_out_of_order: usize,
    /// Time to expire inactive UDP connections (in milliseconds).
    pub(super) udp_inactivity_timeout: usize,
    /// Time to expire inactive TCP connections (in milliseconds).
    pub(super) tcp_inactivity_timeout: usize,
    /// Time to expire unestablished TCP connections (in milliseconds).
    pub(super) tcp_establish_timeout: usize,
    /// Frequency to check for inactive streams (in milliseconds).
    pub(super) timeout_resolution: usize,
}

impl From<&ConnTrackConfig> for TrackerConfig {
    fn from(config: &ConnTrackConfig) -> Self {
        TrackerConfig {
            max_connections: config.max_connections,
            max_out_of_order: config.max_out_of_order,
            udp_inactivity_timeout: config.udp_inactivity_timeout,
            tcp_inactivity_timeout: config.tcp_inactivity_timeout,
            tcp_establish_timeout: config.tcp_establish_timeout,
            timeout_resolution: config.timeout_resolution,
        }
    }
}
