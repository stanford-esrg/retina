//! Memory pools to allocate DPDK message buffers.

use crate::config::MempoolConfig;
use crate::dpdk;
use crate::lcore::SocketId;
use std::cmp;
use std::ffi::{CStr, CString};
use std::fmt;
use std::os::raw::{c_int, c_uint};
use std::ptr::NonNull;

use anyhow::Result;
use thiserror::Error;

const RX_BUF_ALIGN: u32 = 1024;

/// A wrapper around a DPDK `rte_mempool` for packet mbufs.
/// It is recommended to allocate one Mempool per NUMA node.
pub(crate) struct Mempool {
    raw: NonNull<dpdk::rte_mempool>,
}

impl Mempool {
    /// Creates a new mbuf pool on socket_id
    pub(crate) fn new(config: &MempoolConfig, socket_id: SocketId, mtu: usize) -> Result<Self> {
        let data_room = crate::port::mtu_to_max_frame_len(mtu as u32);
        let data_room_aligned = round_up(data_room, RX_BUF_ALIGN);
        let mbuf_size = data_room_aligned + dpdk::RTE_PKTMBUF_HEADROOM;
        let mbuf_size = cmp::max(mbuf_size, dpdk::RTE_MBUF_DEFAULT_BUF_SIZE);

        let name = format!("mempool_{}", socket_id);
        let cname = CString::new(name.clone()).expect("Invalid CString conversion");
        let mempool = unsafe {
            dpdk::rte_pktmbuf_pool_create(
                cname.as_ptr(),
                config.capacity as c_uint,
                config.cache_size as c_uint,
                0,
                mbuf_size as u16,
                socket_id.raw() as c_int,
            )
        };
        Ok(Mempool {
            raw: NonNull::new(mempool).ok_or(MempoolError::Create(name))?,
        })
    }

    /// For DPDK functions
    pub(crate) fn raw(&self) -> &dpdk::rte_mempool {
        unsafe { self.raw.as_ref() }
    }

    /// For DPDK functions
    pub(crate) fn raw_mut(&mut self) -> &mut dpdk::rte_mempool {
        unsafe { self.raw.as_mut() }
    }

    /// Mempool name.
    pub(crate) fn name(&self) -> &str {
        let cstr = unsafe { CStr::from_ptr(self.raw().name.as_ptr()) };
        cstr.to_str().unwrap()
    }

    /// Default mbuf size in bytes.
    pub(crate) fn default_mtu() -> usize {
        1500
    }
}

impl Drop for Mempool {
    fn drop(&mut self) {
        log::info!("Dropping {}.", self.name());
        unsafe { dpdk::rte_mempool_free(self.raw_mut()) };
    }
}

impl fmt::Debug for Mempool {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let raw = self.raw();
        f.debug_struct(self.name())
            .field("capacity", &raw.size)
            .field("cache_size", &raw.cache_size)
            .field("socket_id", &raw.socket_id)
            .finish()
    }
}

/// Rounds `n` up to the nearest multiple of `s`
fn round_up(n: u32, s: u32) -> u32 {
    ((n + s - 1) / s) * s
}

#[derive(Error, Debug)]
pub(crate) enum MempoolError {
    #[error("Mempool {0} creation failed")]
    Create(String),

    #[error("Mbuf allocation failed: mempool exhausted.")]
    Exhausted,
}
