//! Packet buffer manipulation.
//!
//! ## Remarks
//! Retina does not support multi-segment Mbufs, but does support setting the maximum Mbuf size in
//! the runtime configuration (see [configuration parameters](crate::config)). However, all Mbufs
//! will be allocated with the specified size, so allowing jumbo frames will limit the maximum
//! number of Mbufs available in the memory pool.
//!
//! This module is adapted from
//! [capsule::Mbuf](https://docs.rs/capsule/0.1.5/capsule/struct.Mbuf.html).

use crate::dpdk;
use crate::memory::mempool::MempoolError;
use crate::protocols::packet::{Packet, PacketHeader, PacketParseError};

use std::fmt;
use std::ptr::NonNull;
use std::slice;

use anyhow::{bail, Result};
use thiserror::Error;

#[derive(Clone)]
/// A packet buffer.
///
/// This is a wrapper around a DPDK message buffer that represents a single Ethernet frame.
pub struct Mbuf {
    raw: NonNull<dpdk::rte_mbuf>,
}

impl Mbuf {
    /// Creates a new Mbuf from rte_mbuf raw pointer. `mbuf` must be non-null.
    pub(crate) fn new_unchecked(mbuf: *mut dpdk::rte_mbuf) -> Mbuf {
        unsafe {
            Mbuf {
                raw: NonNull::new_unchecked(mbuf),
            }
        }
    }

    /// Creates a new Mbuf from rte_mbuf raw pointer.
    pub(crate) fn new(mbuf: *mut dpdk::rte_mbuf) -> Result<Mbuf> {
        Ok(Mbuf {
            raw: NonNull::new(mbuf).ok_or(MempoolError::Exhausted)?,
        })
    }

    /// Creates a new Mbuf from a byte slice.
    pub(crate) fn from_bytes(data: &[u8], mp: *mut dpdk::rte_mempool) -> Result<Mbuf> {
        let mut mbuf = unsafe { Mbuf::new(dpdk::rte_pktmbuf_alloc(mp))? };
        if data.len() <= mbuf.raw().buf_len.into() {
            mbuf.raw_mut().data_len += data.len() as u16;
            mbuf.raw_mut().pkt_len += data.len() as u32;
            unsafe {
                let src = data.as_ptr();
                let dst = mbuf.get_data_address(0) as *mut u8;
                std::ptr::copy_nonoverlapping(src, dst, data.len());
            }
        } else {
            bail!(MbufError::WritePastBuffer);
        }
        Ok(mbuf)
    }

    /// Returns a reference to the inner rte_mbuf for use with DPDK functions.
    pub(crate) fn raw(&self) -> &dpdk::rte_mbuf {
        unsafe { self.raw.as_ref() }
    }

    /// Returns a mutable reference to the inner rte_mbuf.
    fn raw_mut(&mut self) -> &mut dpdk::rte_mbuf {
        unsafe { self.raw.as_mut() }
    }

    /// Returns the UNIX timestamp of the packet.
    #[allow(dead_code)]
    pub(crate) fn timestamp(&self) -> usize {
        unimplemented!();
    }

    /// Returns the length of the data in the Mbuf.
    pub fn data_len(&self) -> usize {
        self.raw().data_len as usize
    }

    /// Returns the contents of the Mbuf as a byte slice.
    pub fn data(&self) -> &[u8] {
        let ptr = self.get_data_address(0) as *const u8;
        unsafe { slice::from_raw_parts(ptr, self.data_len()) as &[u8] }
    }

    /// Returns a byte slice of data with length count at offset.
    ///
    /// Errors if `offset` is greater than or equal to the buffer length or `count` exceeds the size
    /// of the data stored at `offset`.
    pub fn get_data_slice(&self, offset: usize, count: usize) -> Result<&[u8]> {
        if offset < self.data_len() {
            if offset + count <= self.data_len() {
                let ptr = self.get_data_address(offset) as *const u8;
                unsafe { Ok(slice::from_raw_parts(ptr, count) as &[u8]) }
            } else {
                bail!(MbufError::ReadPastBuffer)
            }
        } else {
            bail!(MbufError::BadOffset)
        }
    }

    /// Reads the data at `offset` as `T` and returns it as a raw pointer. Errors if `offset` is
    /// greater than or equal to the buffer length or the size of `T` exceeds the size of the data
    /// stored at `offset`.
    pub(crate) fn get_data<T: PacketHeader>(&self, offset: usize) -> Result<*const T> {
        if offset < self.data_len() {
            if offset + T::size_of() <= self.data_len() {
                Ok(self.get_data_address(offset) as *const T)
            } else {
                bail!(MbufError::ReadPastBuffer)
            }
        } else {
            bail!(MbufError::BadOffset)
        }
    }

    /// Returns the raw pointer from the offset.
    fn get_data_address(&self, offset: usize) -> *const u8 {
        let raw = self.raw();
        unsafe { (raw.buf_addr as *const u8).offset(raw.data_off as isize + offset as isize) }
    }

    /// Returns the RSS hash of the Mbuf computed by the NIC.
    #[allow(dead_code)]
    pub(crate) fn rss_hash(&self) -> u32 {
        unsafe { self.raw().__bindgen_anon_2.hash.rss }
    }

    /// Returns any MARKs tagged on the Mbuf by the NIC.
    #[allow(dead_code)]
    pub(crate) fn mark(&self) -> u32 {
        unsafe { self.raw().__bindgen_anon_2.hash.fdir.hi }
    }
}

impl<'a> Packet<'a> for Mbuf {
    fn mbuf(&self) -> &Mbuf {
        self
    }

    fn header_len(&self) -> usize {
        0
    }

    fn next_header_offset(&self) -> usize {
        0
    }

    fn next_header(&self) -> Option<usize> {
        None
    }

    fn parse_from(_outer: &'a impl Packet<'a>) -> Result<Self>
    where
        Self: Sized,
    {
        // parse_from should never be called for Mbuf.
        bail!(PacketParseError::InvalidProtocol)
    }
}

impl Drop for Mbuf {
    fn drop(&mut self) {
        // log::debug!("Dropping a Mbuf, freeing mbuf@{:p}", self.raw().buf_addr);
        unsafe { dpdk::rte_pktmbuf_free(self.raw()) };
    }
}

impl fmt::Debug for Mbuf {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let raw = self.raw();
        f.debug_struct("Mbuf")
            .field("buf_addr", &raw.buf_addr)
            .field("buf_len", &raw.buf_len)
            .field("pkt_len", &raw.pkt_len)
            .field("data_len", &raw.data_len)
            .field("data_off", &raw.data_off)
            .finish()
    }
}

// displays the actual packet data of the frame (first segment only)
impl fmt::Display for Mbuf {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in 0..self.raw().data_len {
            write!(
                f,
                "{:02x} ",
                self.get_data_slice(byte as usize, 1).unwrap()[0]
            )?;
            if byte % 16 == 15 {
                writeln!(f,)?;
            }
        }
        Ok(())
    }
}

#[derive(Error, Debug)]
pub(crate) enum MbufError {
    #[error("Offset exceeds Mbuf segment buffer length")]
    BadOffset,

    #[error("Data read exceeds Mbuf segment buffer")]
    ReadPastBuffer,

    #[error("Data write exceeds Mbuf segment buffer")]
    WritePastBuffer,
}
