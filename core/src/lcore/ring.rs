use crate::dpdk;
use crate::lcore::SocketId;

use anyhow::{bail, Result};
use std::ffi::{CStr, CString};
use std::fmt;
use std::os::raw::{c_int, c_uint, c_void};
use std::ptr::NonNull;

/// A wrapper around a ring structure
pub(crate) struct Ring {
    raw: NonNull<dpdk::rte_ring>,
}

unsafe impl Send for Ring {}
unsafe impl Sync for Ring {}

impl Ring {
    pub(crate) fn new(size: u32, socket_id: SocketId, flags: u32) -> Result<Self> {
        if size == 0 || ((size & size - 1) != 0) {
            bail!("Ring size must be a power of 2");
        }

        let name = format!("event_ring_{}", socket_id);
        let cname = CString::new(name.clone()).unwrap();
        log::debug!("Ring size: {}", size);
        let ring = unsafe {
            dpdk::rte_ring_create(
                cname.as_ptr(),
                size,
                socket_id.raw() as c_int,
                flags as c_uint,
            )
        };

        let ring_nn = NonNull::new(ring);
        match ring_nn {
            Some(raw) => Ok(Ring { raw }),
            None => bail!("Failed to create ring {}", name),
        }
    }

    /// For DPDK functions
    pub(crate) fn raw(&self) -> &dpdk::rte_ring {
        unsafe { self.raw.as_ref() }
    }

    /// For DPDK functions
    pub(crate) fn raw_mut(&mut self) -> &mut dpdk::rte_ring {
        unsafe { self.raw.as_mut() }
    }

    /// Returns the name of the Ring
    pub(crate) fn name(&self) -> &str {
        let cstr = unsafe { CStr::from_ptr(self.raw().name.as_ptr()) };
        cstr.to_str().unwrap()
    }

    /// Returns the size of the data store used by the ring (NOT the usable space)
    pub(crate) fn size(&self) -> u32 {
        unsafe { dpdk::rte_ring_get_size(self.raw()) as u32 }
    }

    /// Returns the number of objects can be stored in the ring
    pub(crate) fn capacity(&self) -> u32 {
        unsafe { dpdk::rte_ring_get_capacity(self.raw()) as u32 }
    }

    /// Returns `true` if the ring is full
    pub(crate) fn is_full(&self) -> bool {
        unsafe { dpdk::rte_ring_full(self.raw()) == 1 }
    }

    /// Returns `true` if the ring is empty
    pub(crate) fn is_empty(&self) -> bool {
        unsafe { dpdk::rte_ring_empty(self.raw()) == 1 }
    }

    /// Returns the number of entries in the ring
    pub(crate) fn count(&self) -> u32 {
        unsafe { dpdk::rte_ring_count(self.raw()) as u32 }
    }

    /// Returns the number of free entries in the ring
    pub(crate) fn free_count(&self) -> u32 {
        unsafe { dpdk::rte_ring_free_count(self.raw()) as u32 }
    }

    /// Enqueue object of type `T` onto the ring (multi-producers safe)
    pub(crate) fn mp_enqueue<T>(&mut self, obj: T) -> Result<()> {
        let ret = unsafe {
            dpdk::rte_ring_mp_enqueue(
                self.raw_mut(),
                Box::into_raw(Box::new(obj)) as *mut _ as *mut c_void,
            )
        };
        if ret != 0 {
            bail!("Failed to enqueue object");
        }
        Ok(())
    }

    /// Enqueue object of type `T` onto the ring (NOT multi-producers safe)
    pub(crate) fn sp_enqueue<T>(&mut self, obj: T) -> Result<()> {
        let ret = unsafe {
            dpdk::rte_ring_sp_enqueue(
                self.raw_mut(),
                Box::into_raw(Box::new(obj)) as *mut _ as *mut c_void,
            )
        };
        if ret != 0 {
            bail!("Failed to enqueue object");
        }
        Ok(())
    }

    /// Dequeue one object from the ring and return it as `T` (multi-consumers safe)
    pub(crate) fn mc_dequeue<T>(&mut self) -> Result<T> {
        let mut ptr: *mut c_void = std::ptr::null_mut();
        let tmp: *mut *mut c_void = &mut ptr;
        let ret = unsafe { dpdk::rte_ring_mc_dequeue(self.raw_mut(), tmp) };
        if ret != 0 {
            bail!("Nothing to dequeue");
        }
        let obj = unsafe { Box::from_raw(ptr as *mut T) };
        Ok(*obj)
    }

    /// Dequeue one object from the ring and return it as `T` (NOT multi-consumers safe)
    pub(crate) fn sc_dequeue<T>(&mut self) -> Result<T> {
        let mut ptr: *mut c_void = std::ptr::null_mut();
        let tmp: *mut *mut c_void = &mut ptr;
        let ret = unsafe { dpdk::rte_ring_sc_dequeue(self.raw_mut(), tmp) };
        if ret != 0 {
            bail!("Nothing to dequeue");
        }
        let obj = unsafe { Box::from_raw(ptr as *mut T) };
        Ok(*obj)
    }
}

impl Drop for Ring {
    fn drop(&mut self) {
        log::info!("Dropping {}.", self.name());
        unsafe { dpdk::rte_ring_free(self.raw_mut()) };
    }
}

impl fmt::Debug for Ring {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct(self.name())
            .field("size", &self.size())
            .field("capacity", &self.capacity())
            .field("count", &self.count())
            .field("free_count", &self.free_count())
            .field("is_full", &self.is_full())
            .field("is_empty", &self.is_empty())
            .finish()
    }
}
