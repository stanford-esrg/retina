#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(unused)]
// Bindgen generates functions with u128 return types
#![allow(improper_ctypes)]

include!(concat!(env!("OUT_DIR"), "/dpdk.rs"));

use std::os::raw::{c_char, c_int, c_uint, c_void};

#[cfg(dpdk_ge_2311)]
impl std::fmt::Debug for rte_gtp_psc_generic_hdr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("rte_gtp_psc_generic_hdr")
            .field("ext_hdr_len", &self.ext_hdr_len)
            .field("_bitfield_align_1", &self._bitfield_align_1)
            .field("_bitfield_1", &self._bitfield_1)
            .field("data", &self.data)
            .finish()
    }
}

impl rte_ipv4_hdr {
    #[cfg(not(dpdk_ge_2311))]
    pub fn set_version_ihl(&mut self, version_ihl: u8) {
        self.version_ihl = version_ihl;
    }

    #[cfg(dpdk_ge_2311)]
    pub fn set_version_ihl(&mut self, version_ihl: u8) {
        self.__bindgen_anon_1.version_ihl = version_ihl;
    }
}

// Bindgen doesn't support complex macros, so we need these
pub const RTE_ETH_RSS_IPV4: u64 = 1 << 2;
pub const RTE_ETH_RSS_FRAG_IPV4: u64 = 1 << 3;
pub const RTE_ETH_RSS_NONFRAG_IPV4_TCP: u64 = 1 << 4;
pub const RTE_ETH_RSS_NONFRAG_IPV4_UDP: u64 = 1 << 5;
pub const RTE_ETH_RSS_NONFRAG_IPV4_SCTP: u64 = 1 << 6;
pub const RTE_ETH_RSS_NONFRAG_IPV4_OTHER: u64 = 1 << 7;
pub const RTE_ETH_RSS_IPV6: u64 = 1 << 8;
pub const RTE_ETH_RSS_FRAG_IPV6: u64 = 1 << 9;
pub const RTE_ETH_RSS_NONFRAG_IPV6_TCP: u64 = 1 << 10;
pub const RTE_ETH_RSS_NONFRAG_IPV6_UDP: u64 = 1 << 11;
pub const RTE_ETH_RSS_NONFRAG_IPV6_SCTP: u64 = 1 << 12;
pub const RTE_ETH_RSS_NONFRAG_IPV6_OTHER: u64 = 1 << 13;
pub const RTE_ETH_RSS_L2_PAYLOAD: u64 = 1 << 14;
pub const RTE_ETH_RSS_IPV6_EX: u64 = 1 << 15;
pub const RTE_ETH_RSS_IPV6_TCP_EX: u64 = 1 << 16;
pub const RTE_ETH_RSS_IPV6_UDP_EX: u64 = 1 << 17;
pub const RTE_ETH_RSS_PORT: u64 = 1 << 18;
pub const RTE_ETH_RSS_VXLAN: u64 = 1 << 19;
pub const RTE_ETH_RSS_GENEVE: u64 = 1 << 20;
pub const RTE_ETH_RSS_NVGRE: u64 = 1 << 21;
pub const RTE_ETH_RSS_GTPU: u64 = 1 << 23;
pub const RTE_ETH_RSS_ETH: u64 = 1 << 24;
pub const RTE_ETH_RSS_S_VLAN: u64 = 1 << 25;
pub const RTE_ETH_RSS_C_VLAN: u64 = 1 << 26;
pub const RTE_ETH_RSS_ESP: u64 = 1 << 27;
pub const RTE_ETH_RSS_AH: u64 = 1 << 28;
pub const RTE_ETH_RSS_L2TPV3: u64 = 1 << 29;
pub const RTE_ETH_RSS_PFCP: u64 = 1 << 30;
pub const RTE_ETH_RSS_PPPOE: u64 = 1 << 31;
pub const RTE_ETH_RSS_ECPRI: u64 = 1 << 32;
pub const RTE_ETH_RSS_MPLS: u64 = 1 << 33;
pub const RTE_ETH_RSS_IPV4_CHKSUM: u64 = 1 << 34;
pub const RTE_ETH_RSS_IP: u64 = RTE_ETH_RSS_IPV4
    | RTE_ETH_RSS_FRAG_IPV4
    | RTE_ETH_RSS_NONFRAG_IPV4_OTHER
    | RTE_ETH_RSS_IPV6
    | RTE_ETH_RSS_FRAG_IPV6
    | RTE_ETH_RSS_NONFRAG_IPV6_OTHER
    | RTE_ETH_RSS_IPV6_EX;
pub const RTE_ETH_RSS_TCP: u64 =
    RTE_ETH_RSS_NONFRAG_IPV4_TCP | RTE_ETH_RSS_NONFRAG_IPV6_TCP | RTE_ETH_RSS_IPV6_TCP_EX;
pub const RTE_ETH_RSS_UDP: u64 =
    RTE_ETH_RSS_NONFRAG_IPV4_UDP | RTE_ETH_RSS_NONFRAG_IPV6_UDP | RTE_ETH_RSS_IPV6_UDP_EX;

#[cfg(dpdk_ge_2311)]
pub use rte_eth_fc_mode_RTE_ETH_FC_NONE as rte_eth_fc_mode_RTE_FC_NONE;
#[cfg(dpdk_ge_2311)]
pub use rte_eth_rx_mq_mode_RTE_ETH_MQ_RX_RSS as rte_eth_rx_mq_mode_ETH_MQ_RX_RSS;
#[cfg(dpdk_ge_2311)]
pub use RTE_ETH_RETA_GROUP_SIZE as RTE_RETA_GROUP_SIZE;
#[cfg(dpdk_ge_2311)]
pub use RTE_ETH_VLAN_STRIP_OFFLOAD as DEV_RX_OFFLOAD_VLAN_STRIP;

#[link(name = "inlined")]
extern "C" {
    fn rte_pktmbuf_free_(packet: *const rte_mbuf);
    fn rte_pktmbuf_alloc_(mp: *mut rte_mempool) -> *mut rte_mbuf;
    fn rte_eth_tx_burst_(
        port_id: u16,
        queue_id: u16,
        tx_pkts: *mut *mut rte_mbuf,
        nb_pkts: u16,
    ) -> u16;
    fn rte_eth_rx_burst_(
        port_id: u16,
        queue_id: u16,
        rx_pkts: *mut *mut rte_mbuf,
        nb_pkts: u16,
    ) -> u16;
    fn rte_mbuf_refcnt_read_(m: *const rte_mbuf) -> u16;
    fn rte_mbuf_refcnt_update_(m: *mut rte_mbuf, value: i16) -> u16;
    fn rte_pktmbuf_adj_(packet: *mut rte_mbuf, len: u16) -> *mut c_char;
    fn rte_pktmbuf_trim_(packet: *mut rte_mbuf, len: u16) -> c_int;
    fn rte_lcore_id_() -> u16;
    fn rte_rdtsc_() -> u64;
    fn rte_ring_enqueue_(ring: *mut rte_ring, obj: *mut c_void) -> c_int;
    fn rte_ring_sp_enqueue_(ring: *mut rte_ring, obj: *mut c_void) -> c_int;
    fn rte_ring_mp_enqueue_(ring: *mut rte_ring, obj: *mut c_void) -> c_int;
    fn rte_ring_dequeue_(ring: *mut rte_ring, obj_p: *mut *mut c_void) -> c_int;
    fn rte_ring_sc_dequeue_(ring: *mut rte_ring, obj_p: *mut *mut c_void) -> c_int;
    fn rte_ring_mc_dequeue_(ring: *mut rte_ring, obj_p: *mut *mut c_void) -> c_int;
    fn rte_ring_count_(ring: *const rte_ring) -> c_uint;
    fn rte_ring_free_count_(ring: *const rte_ring) -> c_uint;
    fn rte_ring_full_(ring: *const rte_ring) -> c_int;
    fn rte_ring_empty_(ring: *const rte_ring) -> c_int;
    fn rte_ring_get_size_(ring: *const rte_ring) -> c_uint;
    fn rte_ring_get_capacity_(ring: *const rte_ring) -> c_uint;
}

#[cfg(feature = "mlx5")]
#[link(name = "rte_net_mlx5")]
extern "C" {
    fn rte_pmd_mlx5_get_dyn_flag_names();
}

#[cfg(feature = "mlx5")]
#[inline(never)]
pub fn load_drivers() {
    if std::env::var("DONT_SET_THIS").is_ok() {
        unsafe {
            rte_pmd_mlx5_get_dyn_flag_names();
        }
    }
}

#[cfg(not(feature = "mlx5"))]
#[inline(never)]
pub fn load_drivers() {}

#[inline]
pub unsafe fn rte_pktmbuf_free(packet: *const rte_mbuf) {
    rte_pktmbuf_free_(packet)
}

#[inline]
pub unsafe fn rte_pktmbuf_alloc(mp: *mut rte_mempool) -> *mut rte_mbuf {
    rte_pktmbuf_alloc_(mp)
}

#[inline]
pub unsafe fn rte_eth_tx_burst(
    port_id: u16,
    queue_id: u16,
    tx_pkts: *mut *mut rte_mbuf,
    nb_pkts: u16,
) -> u16 {
    rte_eth_tx_burst_(port_id, queue_id, tx_pkts, nb_pkts)
}

#[inline]
pub unsafe fn rte_eth_rx_burst(
    port_id: u16,
    queue_id: u16,
    rx_pkts: *mut *mut rte_mbuf,
    nb_pkts: u16,
) -> u16 {
    rte_eth_rx_burst_(port_id, queue_id, rx_pkts, nb_pkts)
}

#[inline]
pub unsafe fn rte_mbuf_refcnt_read(m: *const rte_mbuf) -> u16 {
    rte_mbuf_refcnt_read_(m)
}

#[inline]
pub unsafe fn rte_mbuf_refcnt_update(m: *mut rte_mbuf, value: i16) -> u16 {
    rte_mbuf_refcnt_update_(m, value)
}

#[inline]
pub unsafe fn rte_pktmbuf_adj(packet: *mut rte_mbuf, len: u16) -> *mut c_char {
    rte_pktmbuf_adj_(packet, len)
}

#[inline]
pub unsafe fn rte_pktmbuf_trim(packet: *mut rte_mbuf, len: u16) -> c_int {
    rte_pktmbuf_trim_(packet, len)
}
/// Returns the application thread ID of the execution unit.
///
/// In most cases, the lcore ID returned will correspond to the processor ID of the CPU
/// on which the thread is pinned, but this will not be the case if the user has explicitly
/// changed the thread-to-core affinities.
///
/// ## Remarks
/// This is `unsafe` because it calls the DPDK `rte_lcore_id()` function via FFI. Use at your
/// own risk.
#[inline]
pub unsafe fn rte_lcore_id() -> u16 {
    rte_lcore_id_()
}

/// Reads the timestamp counter (TSC) register.
///
/// This is a low-overhead way to get CPU timing information, but may not be available on all
/// platforms and could be imprecise. It should only be used to approximate cycle counts.
///
/// ## Remarks
/// This is `unsafe` because it calls the DPDK `rte_rdtsc()` function via FFI. Use at your own risk.
#[inline]
pub unsafe fn rte_rdtsc() -> u64 {
    rte_rdtsc_()
}

/* RTE_RING functions */

#[inline]
pub unsafe fn rte_ring_enqueue(ring: *mut rte_ring, obj: *mut c_void) -> c_int {
    rte_ring_enqueue_(ring, obj)
}

#[inline]
pub unsafe fn rte_ring_sp_enqueue(ring: *mut rte_ring, obj: *mut c_void) -> c_int {
    rte_ring_sp_enqueue_(ring, obj)
}

#[inline]
pub unsafe fn rte_ring_mp_enqueue(ring: *mut rte_ring, obj: *mut c_void) -> c_int {
    rte_ring_mp_enqueue_(ring, obj)
}

#[inline]
pub unsafe fn rte_ring_dequeue(ring: *mut rte_ring, obj_p: *mut *mut c_void) -> c_int {
    rte_ring_dequeue_(ring, obj_p)
}

#[inline]
pub unsafe fn rte_ring_sc_dequeue(ring: *mut rte_ring, obj_p: *mut *mut c_void) -> c_int {
    rte_ring_sc_dequeue_(ring, obj_p)
}

#[inline]
pub unsafe fn rte_ring_mc_dequeue(ring: *mut rte_ring, obj_p: *mut *mut c_void) -> c_int {
    rte_ring_mc_dequeue_(ring, obj_p)
}

#[inline]
pub unsafe fn rte_ring_count(ring: *const rte_ring) -> c_uint {
    rte_ring_count_(ring)
}

#[inline]
pub unsafe fn rte_ring_free_count(ring: *const rte_ring) -> c_uint {
    rte_ring_free_count_(ring)
}

#[inline]
pub unsafe fn rte_ring_full(ring: *const rte_ring) -> c_int {
    rte_ring_full_(ring)
}

#[inline]
pub unsafe fn rte_ring_empty(ring: *const rte_ring) -> c_int {
    rte_ring_empty_(ring)
}

#[inline]
pub unsafe fn rte_ring_get_size(ring: *const rte_ring) -> c_uint {
    rte_ring_get_size_(ring)
}

#[inline]
pub unsafe fn rte_ring_get_capacity(ring: *const rte_ring) -> c_uint {
    rte_ring_get_capacity_(ring)
}
