pub(crate) mod monitor;
// pub(crate) mod ring;
pub(crate) mod rx_core;

use crate::dpdk;

use std::fmt;

use serde::{Deserialize, Serialize};

#[derive(Debug, Copy, Clone, Hash, Ord, Eq, PartialEq, PartialOrd)]
pub(crate) struct SocketId(pub(crate) u32);

impl SocketId {
    // For DPDK functions
    pub(crate) fn raw(&self) -> u32 {
        self.0
    }
}

impl fmt::Display for SocketId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/* --------------------------------------------------------------------------------- */

#[derive(Debug, Copy, Clone, Hash, Ord, Eq, PartialEq, PartialOrd, Deserialize, Serialize)]
pub struct CoreId(pub u32);

impl CoreId {
    pub(crate) fn socket_id(&self) -> SocketId {
        unsafe { SocketId(dpdk::rte_lcore_to_socket_id(self.0)) }
    }

    /// For DPDK functions
    pub fn raw(&self) -> u32 {
        self.0
    }
}

impl fmt::Display for CoreId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}
