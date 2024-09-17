use crate::config::{ConnTrackConfig, OfflineConfig};
use crate::conntrack::{ConnTracker, TrackerConfig};
use crate::dpdk;
use crate::lcore::{CoreId, SocketId};
use crate::memory::mbuf::Mbuf;
use crate::memory::mempool::Mempool;
use crate::subscription::*;

use std::collections::BTreeMap;
use std::ffi::CString;
use std::sync::Arc;

use cpu_time::ProcessTime;
use pcap::Capture;

pub(crate) struct OfflineRuntime<S>
where
    S: Subscribable,
{
    pub(crate) mempool_name: String,
    pub(crate) subscription: Arc<Subscription<S>>,
    pub(crate) options: OfflineOptions,
    id: CoreId,
}

impl<S> OfflineRuntime<S>
where
    S: Subscribable,
{
    pub(crate) fn new(
        options: OfflineOptions,
        mempools: &BTreeMap<SocketId, Mempool>,
        subscription: Arc<Subscription<S>>,
    ) -> Self {
        let core_id = CoreId(unsafe { dpdk::rte_lcore_id() } as u32);
        let mempool_name = mempools
            .get(&core_id.socket_id())
            .expect("Get offline mempool")
            .name()
            .to_string();
        OfflineRuntime {
            mempool_name,
            subscription,
            options,
            id: core_id,
        }
    }

    pub(crate) fn run(&self) {
        log::info!(
            "Launched offline analysis. Processing pcap: {}",
            self.options.offline.pcap,
        );

        let mut nb_pkts = 0;
        let mut nb_bytes = 0;

        let config = TrackerConfig::from(&self.options.conntrack);
        let registry = S::Tracked::parsers();
        log::debug!("{:#?}", registry);
        let mut stream_table = ConnTracker::<S::Tracked>::new(config, registry, self.id);

        let mempool_raw = self.get_mempool_raw();
        let pcap = self.options.offline.pcap.as_str();
        let mut cap = Capture::from_file(pcap).expect("Error opening pcap. Aborting.");
        let start = ProcessTime::try_now().expect("Getting process time failed");
        while let Ok(frame) = cap.next() {
            if frame.header.len as usize > self.options.offline.mtu {
                continue;
            }
            let mbuf = Mbuf::from_bytes(frame.data, mempool_raw)
                .expect("Unable to allocate mbuf. Try increasing mempool size.");
            nb_pkts += 1;
            nb_bytes += mbuf.data_len() as u64;

            /* Apply the packet filter to get actions */
            let actions = self.subscription.continue_packet(&mbuf, &self.id);
            if !actions.drop() {
                self.subscription
                    .process_packet(mbuf, &mut stream_table, actions);
            }
        }

        // // Deliver remaining data in table
        stream_table.drain(&self.subscription);
        let cpu_time = start.elapsed();
        println!("Processed: {} pkts, {} bytes", nb_pkts, nb_bytes);
        println!("CPU time: {:?}ms", cpu_time.as_millis());
    }

    fn get_mempool_raw(&self) -> *mut dpdk::rte_mempool {
        let cname = CString::new(self.mempool_name.clone()).expect("Invalid CString conversion");
        unsafe { dpdk::rte_mempool_lookup(cname.as_ptr()) }
    }
}

/// Read-only runtime options for the offline core
#[derive(Debug)]
pub(crate) struct OfflineOptions {
    pub(crate) offline: OfflineConfig,
    pub(crate) conntrack: ConnTrackConfig,
}
