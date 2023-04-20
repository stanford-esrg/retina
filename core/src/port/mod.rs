#[allow(dead_code)]
mod info;
pub(crate) mod statistics;

use crate::config::PortMap;
use crate::dpdk;
use crate::lcore::{CoreId, SocketId};
use crate::memory::mempool::Mempool;

use self::info::PortInfo;

use std::cmp;
use std::collections::BTreeMap;
use std::convert::TryInto;
use std::ffi::CString;
use std::fmt;
use std::mem;
use std::ptr;

use anyhow::{bail, Result};

const RSS_KEY_LEN: usize = 40;
pub(crate) const SYMMETRIC_RSS_KEY: [u8; RSS_KEY_LEN] = [
    0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
    0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
    0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
];
const RSS_RETA_SIZE: usize = 512;

#[derive(Debug, Copy, Clone, Hash, Ord, Eq, PartialEq, PartialOrd)]
pub(crate) struct PortId(pub(crate) u16);

impl PortId {
    pub fn new_from_device(device: String) -> PortId {
        let mut port_id: u16 = 0;
        unsafe {
            let dev_name = CString::new(device).unwrap();
            let ret = dpdk::rte_eth_dev_get_port_by_name(dev_name.as_ptr(), &mut port_id);
            assert_eq!(ret, 0);
        }

        if { unsafe { dpdk::rte_eth_dev_is_valid_port(port_id) } } == 0 {
            panic!("ERROR: Invalid port.");
        }
        PortId(port_id)
    }

    pub(crate) fn socket_id(&self) -> SocketId {
        unsafe { SocketId(dpdk::rte_eth_dev_socket_id(self.raw()) as u32) }
    }

    /// For DPDK functions
    pub(crate) fn raw(&self) -> u16 {
        self.0
    }
}

impl fmt::Display for PortId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/* --------------------------------------------------------------------------------- */

#[derive(Debug)]
pub(crate) struct Port {
    /// Port ID
    pub(crate) id: PortId,

    /// Device PCI ID
    pub(crate) device: String,

    /// Mapping of receive queues to cores
    pub(crate) queue_map: BTreeMap<RxQueue, CoreId>,

    /// Redirection table mapping RSS bucket IDs to RxQueueIds
    pub(crate) reta: [RxQueueId; RSS_RETA_SIZE],
}

impl Port {
    pub(crate) fn new(port_map: &PortMap) -> Port {
        let port_id = PortId::new_from_device(port_map.device.clone());

        let mut queue_map: BTreeMap<RxQueue, CoreId> = BTreeMap::new();
        let mut rx_core_ids = port_map.cores.to_vec();
        rx_core_ids.sort_unstable();
        rx_core_ids.dedup();

        // TODO: display warning if cores do not match port socket
        // TODO: display warning and handle duplicate cores per port and across ports
        let mut q: u16 = 0;
        let nb_buckets = if let Some(sink) = &port_map.sink {
            queue_map.insert(
                RxQueue::new(port_id, RxQueueId(q), RxQueueType::Sink),
                CoreId(sink.core),
            );
            q += 1;
            sink.nb_buckets
        } else {
            RSS_RETA_SIZE
        };

        for core_id in rx_core_ids.iter() {
            queue_map.insert(
                RxQueue::new(port_id, RxQueueId(q), RxQueueType::Receive),
                CoreId(*core_id),
            );
            q += 1;
        }

        if nb_buckets < rx_core_ids.len() {
            log::error!("Requested number of RX redirection table buckets ({}) less than number of RX queues ({}).", nb_buckets, rx_core_ids.len());
            panic!();
        }
        if nb_buckets > RSS_RETA_SIZE {
            log::error!("Requested number of RX redirection table buckets ({}) greater than redirection table capacity ({}).", nb_buckets, RSS_RETA_SIZE);
            panic!();
        }

        if nb_buckets % rx_core_ids.len() != 0 {
            log::warn!("Requested number of RX redirection table buckets ({}) not a multiple of number of RX queues ({}). May result in poor load balancing.", nb_buckets, rx_core_ids.len());
        }

        // Set RSS redirection table
        let mut reta = [RxQueueId(0); RSS_RETA_SIZE];
        let rx_queues: Vec<RxQueueId> = queue_map
            .keys()
            .filter(|rxq| rxq.ty == RxQueueType::Receive)
            .map(|rxq| rxq.qid)
            .collect();
        for i in 0..nb_buckets {
            reta[i] = rx_queues[i % rx_queues.len()];
        }

        log::debug!("{:?}", reta);

        Port {
            id: port_id,
            device: port_map.device.clone(),
            queue_map,
            reta,
        }
    }

    /// Configure port and setup RX queues.
    pub(crate) fn init(
        &self,
        mempools: &mut BTreeMap<SocketId, Mempool>,
        nb_rxd: usize,
        mtu: usize,
        promiscuous: bool,
    ) -> Result<()> {
        self.configure(promiscuous, mtu)?;

        let mempool = mempools.get_mut(&self.id.socket_id()).unwrap();
        self.setup_queues(mempool, nb_rxd)?;
        self.display_info();
        Ok(())
    }

    /// Start port
    pub(crate) fn start(&self) {
        let ret = unsafe { dpdk::rte_eth_dev_start(self.id.raw()) };
        if ret != 0 {
            panic!("Failed to start Port {}", self.id);
        }
        log::info!("Port {} ({}) started.", self.id, self.device);

        self.disable_flow_ctrl();
        self.configure_rss_reta();
    }

    /// Flush flow rules and stop port
    pub(crate) fn stop(&self) {
        log::info!("Flushing hardware flow rules on Port {}...", self.id);
        let mut error: dpdk::rte_flow_error = unsafe { mem::zeroed() };
        let ret = unsafe { dpdk::rte_flow_flush(self.id.raw(), &mut error) };
        if ret != 0 {
            log::error!("Failed to flush hardware rules from Port {}.", self.id);
        }
        let ret = unsafe { dpdk::rte_eth_dev_stop(self.id.raw()) };
        if ret != 0 {
            log::error!("Failed to stop Port {}.", self.id);
        } else {
            log::info!("Port {} ({}) stopped.", self.id, self.device);
        }
    }

    /// Close and free all port resources
    pub(crate) fn close(&self) {
        let ret = unsafe { dpdk::rte_eth_dev_close(self.id.raw()) };
        if ret != 0 {
            log::error!("Failed to close Port {}.", self.id);
        } else {
            log::info!("Port {} ({}) closed.", self.id, self.device);
        }
    }

    /// Display port information
    #[allow(dead_code)]
    pub(crate) fn display_info(&self) {
        let info = PortInfo::collect(self.id);
        match info {
            Ok(info) => info.display(),
            Err(error) => log::error!("{}", error),
        }
    }

    /// Resets physical counters.
    /// Does not reset counters for packets or byte delivered to cores.
    #[allow(dead_code)]
    pub(crate) fn reset_stats(&self) {
        unsafe { dpdk::rte_eth_xstats_reset(self.id.raw()) };
    }

    /// Disables Ethernet flow control on port
    fn disable_flow_ctrl(&self) {
        log::info!("Disabling Ethernet flow control on Port {}...", self.id);
        let prev_mode = {
            let mut fc_conf: dpdk::rte_eth_fc_conf = unsafe { mem::zeroed() };
            let ret = unsafe { dpdk::rte_eth_dev_flow_ctrl_get(self.id.raw(), &mut fc_conf) };
            if ret != 0 {
                log::warn!("Unable to retrieve current flow control status.");
            }
            fc_conf.mode
        };

        // reset flow control config, set to disabled
        let mut fc_conf: dpdk::rte_eth_fc_conf = unsafe { mem::zeroed() };
        fc_conf.mode = dpdk::rte_eth_fc_mode_RTE_FC_NONE;
        let ret = unsafe { dpdk::rte_eth_dev_flow_ctrl_set(self.id.raw(), &mut fc_conf) };
        if ret != 0 {
            log::warn!("Failure disabling flow control.");
        } else if prev_mode == fc_conf.mode {
            log::info!("Ethernet flow control disabled (unchanged).");
        } else {
            log::info!("Ethernet flow control disabled.");
        }
    }

    /// Sets RSS redirection table to full RSS_RETA_SIZE entries
    fn configure_rss_reta(&self) {
        log::info!("Configuring RSS redirection table...");
        const GROUP_SIZE: usize = dpdk::RTE_RETA_GROUP_SIZE as usize;
        let capacity = RSS_RETA_SIZE / GROUP_SIZE;
        let mut reta_conf: Vec<dpdk::rte_eth_rss_reta_entry64> = Vec::with_capacity(capacity);

        for i in 0..capacity {
            let mut reta_entry64: dpdk::rte_eth_rss_reta_entry64 = unsafe { mem::zeroed() };
            reta_entry64.mask = u64::MAX;
            let start = i * GROUP_SIZE;
            let end = (i + 1) * GROUP_SIZE;
            let entry64 = self.reta[start..end]
                .iter()
                .map(|q| q.raw())
                .collect::<Vec<_>>();

            //reta_slice.copy_from_slice(&self.reta[start..end]);
            reta_entry64.reta = entry64.try_into().unwrap();
            reta_conf.push(reta_entry64);
        }

        let ret = unsafe {
            dpdk::rte_eth_dev_rss_reta_update(
                self.id.raw(),
                reta_conf.as_mut_ptr(),
                RSS_RETA_SIZE as u16,
            )
        };
        if ret != 0 {
            if ret == -95 {
                log::warn!("Setting RSS redirection table is not supported for Port {}. Without a symmetrical key and more than one core, you will experience problems matching connections.", self.id);
            } else {
                panic!("Failed to set RSS redirection table for Port {}.", self.id);
            }
        } else {
            log::info!("Configured RSS redirection table.");
        }
    }

    fn configure(&self, promiscuous: bool, mtu: usize) -> Result<()> {
        let mut port_conf: dpdk::rte_eth_conf = unsafe { mem::zeroed() };

        let mut dev_info: dpdk::rte_eth_dev_info = unsafe { std::mem::zeroed() };
        // Safety: foreign function.
        unsafe { dpdk::rte_eth_dev_info_get(self.id.raw(), &mut dev_info) };

        // turn on RSS
        if dev_info.flow_type_rss_offloads != 0 {
            port_conf.rxmode.mq_mode = dpdk::rte_eth_rx_mq_mode_ETH_MQ_RX_RSS;
            port_conf.rx_adv_conf.rss_conf.rss_key = SYMMETRIC_RSS_KEY.as_ptr() as *mut u8;
            port_conf.rx_adv_conf.rss_conf.rss_key_len = RSS_KEY_LEN as u8;
            port_conf.rx_adv_conf.rss_conf.rss_hf =
                (dpdk::ETH_RSS_IP | dpdk::ETH_RSS_TCP | dpdk::ETH_RSS_UDP) as u64;
        }

        let max_rx_pkt_len = mtu_to_max_frame_len(mtu as u32);
        port_conf.rxmode.max_rx_pkt_len = cmp::max(dpdk::RTE_ETHER_MAX_LEN, max_rx_pkt_len);

        // turns on VLAN stripping if supported
        if dev_info.rx_offload_capa & dpdk::DEV_RX_OFFLOAD_VLAN_STRIP as u64 != 0 {
            port_conf.rxmode.offloads |= dpdk::DEV_RX_OFFLOAD_VLAN_STRIP as u64;
        }

        {
            let nb_queues = self.queue_map.len() as u16;
            let ret = unsafe {
                dpdk::rte_eth_dev_configure(self.id.raw(), nb_queues, 0, &port_conf as *const _)
            };
            if ret < 0 {
                bail!("Failed to configure Port {}", self.id);
            }
        }

        // enables or disables promiscuous mode
        if promiscuous {
            let ret = unsafe { dpdk::rte_eth_promiscuous_enable(self.id.raw()) };
            if ret < 0 {
                bail!("Failure enabling promiscuous mode on Port {}", self.id);
            }
        } else {
            let ret = unsafe { dpdk::rte_eth_promiscuous_disable(self.id.raw()) };
            if ret < 0 {
                bail!("Failure disabling promiscuous mode on Port {}", self.id);
            }
        }

        // set MTU to max(1500, requested_mtu)
        let mut set_mtu = cmp::max(dpdk::RTE_ETHER_MTU, mtu as u32);
        if set_mtu > dev_info.max_mtu as u32 {
            set_mtu = dev_info.max_mtu as u32;
            log::warn!("MTU is too big for device that only supports {}", set_mtu);
        }
        if set_mtu < dev_info.min_mtu as u32 {
            set_mtu = dev_info.min_mtu as u32;
            log::warn!("MTU is too small for device that only supports {}", set_mtu);
        }
        let ret = unsafe { dpdk::rte_eth_dev_set_mtu(self.id.raw(), set_mtu as u16) };
        if ret < 0 {
            if ret == -95 {
                log::warn!("Setting MTU is not supported")
            } else {
                bail!(
                    "Failure setting Port {} MTU to {}: Error {}",
                    self.id,
                    set_mtu,
                    ret
                );
            }
        } else {
            log::debug!("Requested MTU: {}, Set MTU: {}", mtu, set_mtu);
            log::debug!("Maximum RX frame size: {}", mtu_to_frame_len(set_mtu));
        }
        Ok(())
    }

    fn setup_queues(&self, mempool: &mut Mempool, nb_rxd: usize) -> Result<()> {
        for rxqueue in self.queue_map.keys() {
            let ret = unsafe {
                dpdk::rte_eth_rx_queue_setup(
                    self.id.raw(),
                    rxqueue.qid.raw(),
                    nb_rxd as u16,
                    self.id.socket_id().raw(),
                    ptr::null(),
                    mempool.raw_mut(),
                )
            };
            if ret < 0 {
                bail!("Failed to setup up RX queue {}", rxqueue);
            }
        }
        Ok(())
    }
}

impl Drop for Port {
    fn drop(&mut self) {
        log::info!("Dropping Port {} ({}).", self.id, self.device);
        self.close();
    }
}

fn mtu_to_frame_len(mtu: u32) -> u32 {
    mtu + dpdk::RTE_ETHER_HDR_LEN + dpdk::RTE_ETHER_CRC_LEN
}

/// Some DPDK drivers require sufficient space in the RX buffer to accomodate 2 VLAN tags
/// for QinQ frames, so set sufficient overhead to accomodate this.
pub(crate) fn mtu_to_max_frame_len(mtu: u32) -> u32 {
    const VLAN_HDR_LEN: u32 = 4;
    mtu + dpdk::RTE_ETHER_HDR_LEN + dpdk::RTE_ETHER_CRC_LEN + 2 * VLAN_HDR_LEN
}

/* --------------------------------------------------------------------------------- */

#[derive(Debug, Copy, Clone, Hash, Ord, Eq, PartialEq, PartialOrd)]
pub(crate) enum RxQueueType {
    /// Packets forwarded to processing pipeline
    Receive,
    /// Throwaway
    Sink,
}

impl fmt::Display for RxQueueType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            RxQueueType::Receive => write!(f, "r"),
            RxQueueType::Sink => write!(f, "s"),
        }
    }
}

#[derive(Debug, Copy, Clone, Hash, Ord, Eq, PartialEq, PartialOrd)]
pub(crate) struct RxQueueId(pub(crate) u16);

impl RxQueueId {
    /// For DPDK functions
    pub(crate) fn raw(&self) -> u16 {
        self.0
    }
}

impl fmt::Display for RxQueueId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Debug, Copy, Clone, Hash, Ord, Eq, PartialEq, PartialOrd)]
pub(crate) struct RxQueue {
    pub(crate) pid: PortId,
    pub(crate) qid: RxQueueId,
    pub(crate) ty: RxQueueType,
}

impl RxQueue {
    pub(crate) fn new(pid: PortId, qid: RxQueueId, ty: RxQueueType) -> Self {
        RxQueue { pid, qid, ty }
    }
}

impl fmt::Display for RxQueue {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "p{}q{}{}", self.pid, self.qid, self.ty)
    }
}
