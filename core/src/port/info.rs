use super::PortId;
use crate::dpdk;

use std::mem;

use anyhow::{bail, Result};

/* --------------------------------------------------------------------------------- */

#[derive(Debug)]
pub(crate) struct PortInfo {
    raw: dpdk::rte_eth_dev_info,
}

impl PortInfo {
    pub(crate) fn collect(port_id: PortId) -> Result<Self> {
        let mut dev_info: dpdk::rte_eth_dev_info = unsafe { mem::zeroed() };
        let ret = unsafe { dpdk::rte_eth_dev_info_get(port_id.raw(), &mut dev_info) };
        if ret < 0 {
            bail!("Failed retrieving port information.");
        }

        Ok(PortInfo { raw: dev_info })
    }

    /// Displays debug output for the raw device information.
    pub(crate) fn display(&self) {
        log::debug!("{:#?}", self.raw);
    }
}
