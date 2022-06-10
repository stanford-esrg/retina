use super::PortId;
use crate::dpdk;

use indexmap::IndexMap;
use std::ffi::CStr;
use std::mem;

use anyhow::{bail, Result};
use colored::*;
use prettytable::{color, format, Attr, Cell, Row, Table};

/// Collects extended statistics
#[derive(Debug)]
pub(crate) struct PortStats {
    pub(crate) stats: IndexMap<String, u64>,
    pub(crate) port_id: PortId,
}

impl PortStats {
    /// Retrieve port statistics at current time
    pub(crate) fn collect(port_id: PortId) -> Result<Self> {
        // temporary table used to get number of available statistics
        let mut table: Vec<dpdk::rte_eth_xstat> = vec![];
        let len = unsafe { dpdk::rte_eth_xstats_get(port_id.raw(), table.as_mut_ptr(), 0) };
        if len < 0 {
            bail!("Invalid Port ID: {}", port_id);
        }

        let mut labels = Vec::with_capacity(len as usize);
        for _ in 0..len {
            let xstat_name: dpdk::rte_eth_xstat_name = unsafe { mem::zeroed() };
            labels.push(xstat_name);
        }

        let nb_labels = unsafe {
            dpdk::rte_eth_xstats_get_names(port_id.raw(), labels.as_mut_ptr(), len as u32)
        };
        if nb_labels < 0 || nb_labels > len {
            bail!("Failed to retrieve port statistics labels.");
        }

        let mut xstats = Vec::with_capacity(len as usize);
        for _ in 0..len {
            let xstat: dpdk::rte_eth_xstat = unsafe { mem::zeroed() };
            xstats.push(xstat);
        }
        let nb_xstats =
            unsafe { dpdk::rte_eth_xstats_get(port_id.raw(), xstats.as_mut_ptr(), len as u32) };
        if nb_xstats < 0 || nb_xstats > len {
            bail!("Failed to retrieve port statistics.");
        }

        if nb_labels != nb_xstats {
            bail!("Number of labels does not match number of retrieved statistics.");
        }

        let mut stats = IndexMap::new();
        for i in 0..nb_xstats {
            let label = unsafe { CStr::from_ptr(labels[i as usize].name.as_ptr()) };
            let value = xstats[i as usize].value;
            stats.insert(label.to_string_lossy().into_owned(), value);
        }
        Ok(PortStats { stats, port_id })
    }

    /// Displays all statistics with keyword in list of keywords
    pub(crate) fn display(&self, keywords: &[String]) {
        if keywords.is_empty() {
            return;
        }
        println!("Port {} statistics", self.port_id);
        self.display_capture_rate();
        self.display_out_of_buffer_rate();
        self.display_discard_rate();

        let mut table = Table::new();
        table.set_format(*format::consts::FORMAT_NO_LINESEP);
        for (label, value) in self.stats.iter() {
            if keywords.iter().any(|k| label.contains(k)) {
                let value_cell = if *value > 0
                    && (label.contains("error")
                        || label.contains("discard")
                        || label.contains("out_of_buffer"))
                {
                    Cell::new_align(&value.to_string(), format::Alignment::RIGHT)
                        .with_style(Attr::ForegroundColor(color::RED))
                } else {
                    Cell::new_align(&value.to_string(), format::Alignment::RIGHT)
                };

                table.add_row(Row::new(vec![value_cell, Cell::new(label)]));
            }
        }
        table.printstd();
    }

    /// Prints fraction of packets received in software.
    /// If no hardware filters are configured, then a value less than one implies
    /// that incoming traffic is arriving too fast for the CPU to handle.
    /// If there are hardware filters configured, then this value indicates that
    /// fraction of total traffic that was filtered by hardware and successfully
    /// delivered to the processing cores.
    pub(super) fn display_capture_rate(&self) {
        let captured = self.stats.get("rx_good_packets");
        let total = self.stats.get("rx_phy_packets");

        match (captured, total) {
            (Some(captured), Some(total)) => {
                let capture_rate = *captured as f64 / *total as f64;
                println!("SW Capture %: {}", capture_rate.to_string().bright_cyan());
            }
            _ => println!("SW Capture %: UNKNOWN"),
        }
    }

    /// Prints fraction of packets discarded by the NIC due to lack of software buffers
    /// available for the incoming packets, aggregated over all RX queues. A non-zero
    /// value implies that the CPU is not consuming packets fast enough. If there are
    /// no hardware filters configured, this value should be 1 - SW Capture %.
    pub(super) fn display_out_of_buffer_rate(&self) {
        let discards = self.stats.get("rx_out_of_buffer");
        let total = self.stats.get("rx_phy_packets");

        match (discards, total) {
            (Some(discards), Some(total)) => {
                let discard_rate = *discards as f64 / *total as f64;

                // arbitrary threshold
                if discard_rate > 0.0001 {
                    println!("Out of Buffer %: {}", discard_rate.to_string().bright_red());
                } else if discard_rate > 0.0 {
                    println!(
                        "Out of Buffer %: {}",
                        discard_rate.to_string().bright_yellow()
                    );
                } else {
                    println!(
                        "Out of Buffer %: {}",
                        discard_rate.to_string().bright_green()
                    );
                }
            }
            _ => println!("Out of Buffer %: UNKNOWN"),
        }
    }

    /// Prints fraction of packets discarded by the NIC due to lack of buffers on
    /// the physical port. A non-zero value implies that the NIC or bus is congested and
    /// cannot absorb the traffic coming from the network. A value of zero may still
    /// indicate that the CPU is not consuming packets fast enough.
    pub(super) fn display_discard_rate(&self) {
        let discards = self.stats.get("rx_phy_discard_packets");
        let total = self.stats.get("rx_phy_packets");

        match (discards, total) {
            (Some(discards), Some(total)) => {
                let discard_rate = *discards as f64 / *total as f64;

                // arbitrary threshold
                if discard_rate > 0.0001 {
                    println!("HW Discard %: {}", discard_rate.to_string().bright_red());
                } else if discard_rate > 0.0 {
                    println!("HW Discard %: {}", discard_rate.to_string().bright_yellow());
                } else {
                    println!("HW Discard %: {}", discard_rate.to_string().bright_green());
                }
            }
            _ => println!("HW Discard %: UNKNOWN"),
        }
    }
}
