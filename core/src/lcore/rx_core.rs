use super::CoreId;
use crate::config::ConnTrackConfig;
use crate::conntrack::{ConnTracker, TrackerConfig};
use crate::dpdk;
use crate::memory::mbuf::Mbuf;
use crate::port::{RxQueue, RxQueueType};
use crate::stats::{
    StatExt, IDLE_CYCLES, IGNORED_BY_PACKET_FILTER_BYTE, IGNORED_BY_PACKET_FILTER_PKT, TOTAL_BYTE,
    TOTAL_CYCLES, TOTAL_PKT,
};
use crate::subscription::*;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Instant;

use itertools::Itertools;

/// A RxCore polls from `rxqueues` and reduces the stream of packets into
/// a stream of higher-level network events to be processed by the user.
pub(crate) struct RxCore<S>
where
    S: Subscribable,
{
    pub(crate) id: CoreId,
    pub(crate) rxqueues: Vec<RxQueue>,
    pub(crate) conntrack: ConnTrackConfig,
    #[cfg(feature = "prometheus")]
    pub(crate) is_prometheus_enabled: bool,
    pub(crate) subscription: Arc<Subscription<S>>,
    pub(crate) is_running: Arc<AtomicBool>,
}

impl<S> RxCore<S>
where
    S: Subscribable,
{
    pub(crate) fn new(
        core_id: CoreId,
        rxqueues: Vec<RxQueue>,
        conntrack: ConnTrackConfig,
        #[cfg(feature = "prometheus")] is_prometheus_enabled: bool,
        subscription: Arc<Subscription<S>>,
        is_running: Arc<AtomicBool>,
    ) -> Self {
        RxCore {
            id: core_id,
            rxqueues,
            conntrack,
            #[cfg(feature = "prometheus")]
            is_prometheus_enabled,
            subscription,
            is_running,
        }
    }

    pub(crate) fn rx_burst(&self, rxqueue: &RxQueue, rx_burst_size: u16) -> Vec<Mbuf> {
        let mut ptrs = Vec::with_capacity(rx_burst_size as usize);
        let nb_rx = unsafe {
            dpdk::rte_eth_rx_burst(
                rxqueue.pid.raw(),
                rxqueue.qid.raw(),
                ptrs.as_mut_ptr(),
                rx_burst_size,
            )
        };
        unsafe {
            ptrs.set_len(nb_rx as usize);
            ptrs.into_iter()
                .map(Mbuf::new_unchecked)
                .collect::<Vec<Mbuf>>()
        }
    }

    pub(crate) fn rx_loop(&self) {
        // TODO: need check to enforce that each core only has same queue types
        if self.rxqueues[0].ty == RxQueueType::Receive {
            self.rx_process();
        } else {
            self.rx_sink();
        }
    }

    fn rx_process(&self) {
        log::info!(
            "Launched RX on core {}, polling {}",
            self.id,
            self.rxqueues.iter().format(", "),
        );

        let mut nb_pkts = 0;
        let mut nb_bytes = 0;

        let config = TrackerConfig::from(&self.conntrack);
        let registry = S::Tracked::parsers();
        log::debug!("{:#?}", registry);
        let mut conn_table = ConnTracker::<S::Tracked>::new(config, registry, self.id);

        let mut now = Instant::now();

        while self.is_running.load(Ordering::Relaxed) {
            for rxqueue in self.rxqueues.iter() {
                let mbufs: Vec<Mbuf> = self.rx_burst(rxqueue, 32);
                if mbufs.is_empty() {
                    IDLE_CYCLES.inc();

                    if IDLE_CYCLES.get() & 1023 == 512 {
                        now = Instant::now();
                    }

                    #[cfg(feature = "prometheus")]
                    if IDLE_CYCLES.get() & 1023 == 0 && self.is_prometheus_enabled {
                        crate::stats::update_thread_local_stats(self.id);
                    }
                }
                TOTAL_CYCLES.inc();
                for mbuf in mbufs.into_iter() {
                    // log::debug!("{:#?}", mbuf);
                    // log::debug!("Mark: {}", mbuf.mark());
                    // log::debug!("RSS Hash: 0x{:x}", mbuf.rss_hash());
                    // log::debug!(
                    //     "Queue ID: {}, Port ID: {}, Core ID: {}",
                    //     rxqueue.qid,
                    //     rxqueue.pid,
                    //     self.id,
                    // );
                    nb_pkts += 1;
                    nb_bytes += mbuf.data_len() as u64;

                    TOTAL_PKT.inc();
                    TOTAL_BYTE.inc_by(mbuf.data_len() as u64);

                    let actions = self.subscription.continue_packet(&mbuf, &self.id);
                    if !actions.drop() {
                        self.subscription
                            .process_packet(mbuf, &mut conn_table, actions);
                    } else {
                        IGNORED_BY_PACKET_FILTER_PKT.inc();
                        IGNORED_BY_PACKET_FILTER_BYTE.inc_by(mbuf.data_len() as u64);
                    }
                }
            }
            conn_table.check_inactive(&self.subscription, now);
        }

        // // Deliver remaining data in table from unfinished connections
        conn_table.drain(&self.subscription);

        log::info!(
            "Core {} total recv from {}: {} pkts, {} bytes",
            self.id,
            self.rxqueues.iter().format(", "),
            nb_pkts,
            nb_bytes
        );
    }

    fn rx_sink(&self) {
        log::info!(
            "Launched SINK on core {}, polling {}",
            self.id,
            self.rxqueues.iter().format(", "),
        );

        let mut nb_pkts = 0;
        let mut nb_bytes = 0;

        while self.is_running.load(Ordering::Relaxed) {
            for rxqueue in self.rxqueues.iter() {
                let mbufs: Vec<Mbuf> = self.rx_burst(rxqueue, 32);
                for mbuf in mbufs.into_iter() {
                    log::debug!("RSS Hash: 0x{:x}", mbuf.rss_hash());
                    log::debug!(
                        "Queue ID: {}, Port ID: {}, Core ID: {}",
                        rxqueue.qid,
                        rxqueue.pid,
                        self.id,
                    );
                    nb_pkts += 1;
                    nb_bytes += mbuf.data_len() as u64;
                }
            }
        }
        log::info!(
            "Sink Core {} total recv from {}: {} pkts, {} bytes",
            self.id,
            self.rxqueues.iter().format(", "),
            nb_pkts,
            nb_bytes
        );
    }
}
