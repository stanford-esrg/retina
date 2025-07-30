use std::ffi::CStr;
use std::mem;
use std::ptr;
use std::net::{IpAddr};

use anyhow::{bail, Result};
use crate::FiveTuple;
use crate::protocols::packet::tcp::TCP_PROTOCOL;
use crate::protocols::packet::udp::UDP_PROTOCOL;

// Use crate-relative paths
use crate::dpdk;
use crate::dpdk::{rte_flow, rte_flow_item, rte_flow_attr, rte_flow_error, rte_flow_create, 
    rte_flow_destroy, rte_flow_action, rte_flow_item_ipv4, rte_flow_item_ipv6, 
    rte_flow_item_tcp, rte_flow_item_udp};

use crate::port::PortId;

// Need to install on all of the NICs (and uninstall)
// Look at config file to get a vec of strings that are pcie addrs
// config = load_config(fname) which gives you runtime config
// config.unline.unwrap().ports << vec of PortMaps .iter.map(blah blah).collect()
// then use this to call new_from_device on each Port and get a vec of PortIds

// Take in vector of PortIds
pub fn install_drop_flow(port_id: &PortId, tuple: &FiveTuple) -> Result<*mut rte_flow> {
    let mut attr: rte_flow_attr = unsafe { mem::zeroed() };
    attr.set_ingress(1);

    // Recommended to declare headers and masks here so they're not dropped prematurely
    let mut ipv4_spec: rte_flow_item_ipv4 = unsafe { mem::zeroed() };
    let mut ipv4_mask: rte_flow_item_ipv4 = unsafe { mem::zeroed() };
    let mut ipv6_spec: rte_flow_item_ipv6 = unsafe { mem::zeroed() };
    let mut ipv6_mask: rte_flow_item_ipv6 = unsafe { mem::zeroed() };
    let mut tcp_spec: rte_flow_item_tcp = unsafe { mem::zeroed() };
    let mut tcp_mask: rte_flow_item_tcp = unsafe { mem::zeroed() };
    let mut udp_spec: rte_flow_item_udp = unsafe { mem::zeroed() };
    let mut udp_mask: rte_flow_item_udp = unsafe { mem::zeroed() };

    let (src_ip, dst_ip) = (tuple.orig.ip(), tuple.resp.ip());
    let (src_port, dst_port) = (tuple.orig.port(), tuple.resp.port());

    // Pattern buffer structure is ETH + [IP] + [L4] + END
    let mut pattern: [rte_flow_item; 5] = unsafe { mem::zeroed() };
    let mut i = 0;

    // ETH
    pattern[i] = rte_flow_item {
        type_: dpdk::rte_flow_item_type_RTE_FLOW_ITEM_TYPE_ETH,
        spec: ptr::null(),
        mask: ptr::null(),
        last: ptr::null(),
    };
    i += 1;

    // Check IP version
    match (src_ip, dst_ip) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => {
            ipv4_spec.hdr.src_addr = u32::from_ne_bytes(src.octets());
            ipv4_spec.hdr.dst_addr = u32::from_ne_bytes(dst.octets());
            ipv4_spec.hdr.next_proto_id = tuple.proto as u8;

            ipv4_mask.hdr.src_addr = u32::MAX;
            ipv4_mask.hdr.dst_addr = u32::MAX;
            ipv4_mask.hdr.next_proto_id = 0xFF;

            pattern[i] = rte_flow_item {
                type_: dpdk::rte_flow_item_type_RTE_FLOW_ITEM_TYPE_IPV4,
                spec: &ipv4_spec as *const _ as *const _,
                mask: &ipv4_mask as *const _ as *const _,
                last: ptr::null(),
            };
            i += 1;
        }
        (IpAddr::V6(src), IpAddr::V6(dst)) => {
            ipv6_spec.hdr.src_addr = dpdk::rte_ipv6_addr { a: src.octets() };
            ipv6_spec.hdr.dst_addr = dpdk::rte_ipv6_addr { a: dst.octets() };
            ipv6_spec.hdr.proto = tuple.proto as u8;

            ipv6_mask.hdr.src_addr = dpdk::rte_ipv6_addr { a: [0xFF; 16] };
            ipv6_mask.hdr.dst_addr = dpdk::rte_ipv6_addr { a: [0xFF; 16] };
            ipv6_mask.hdr.proto = 0xFF;

            pattern[i] = rte_flow_item {
                type_: dpdk::rte_flow_item_type_RTE_FLOW_ITEM_TYPE_IPV6,
                spec: &ipv6_spec as *const _ as *const _,
                mask: &ipv6_mask as *const _ as *const _,
                last: ptr::null(),
            };
            i += 1;
        }
        _ => bail!("Mismatched IP versions"),
    }

    // Check TCP vs UDP
    match tuple.proto {
        TCP_PROTOCOL => {
            tcp_spec.hdr.src_port = src_port.to_be();
            tcp_spec.hdr.dst_port = dst_port.to_be();

            tcp_mask.hdr.src_port = 0xFFFF;
            tcp_mask.hdr.dst_port = 0xFFFF;

            pattern[i] = rte_flow_item {
                type_: dpdk::rte_flow_item_type_RTE_FLOW_ITEM_TYPE_TCP,
                spec: &tcp_spec as *const _ as *const _,
                mask: &tcp_mask as *const _ as *const _,
                last: ptr::null(),
            };
            i += 1;
        }
        UDP_PROTOCOL => {
            udp_spec.hdr.src_port = src_port.to_be();
            udp_spec.hdr.dst_port = dst_port.to_be();

            udp_mask.hdr.src_port = 0xFFFF;
            udp_mask.hdr.dst_port = 0xFFFF;

            pattern[i] = rte_flow_item {
                type_: dpdk::rte_flow_item_type_RTE_FLOW_ITEM_TYPE_UDP,
                spec: &udp_spec as *const _ as *const _,
                mask: &udp_mask as *const _ as *const _,
                last: ptr::null(),
            };
            i += 1;
        }
        _ => bail!("Unsupported protocol {}", tuple.proto),
    }

    // END
    pattern[i] = rte_flow_item {
        type_: dpdk::rte_flow_action_type_RTE_FLOW_ACTION_TYPE_END,
        spec: ptr::null(),
        mask: ptr::null(),
        last: ptr::null(),
    };

    // Actions
    let actions = [
        rte_flow_action {
            type_: dpdk::rte_flow_action_type_RTE_FLOW_ACTION_TYPE_DROP,
            conf: ptr::null(),
        },
        rte_flow_action {
            type_: dpdk::rte_flow_action_type_RTE_FLOW_ACTION_TYPE_END,
            conf: ptr::null(),
        },
    ];

    // Create flow rule using pattern
    let mut error: rte_flow_error = unsafe { mem::zeroed() };
    let flow = unsafe {
        rte_flow_create(
            port_id.raw(),
            &attr,
            pattern.as_ptr(),
            actions.as_ptr(),
            &mut error,
        )
    };

    if flow.is_null() {
        let msg = unsafe { CStr::from_ptr(error.message) }.to_string_lossy();
        bail!("Failed to install flow: {}", msg);
    }

    println!(
        "Installed DROP rule for {}:{} → {}:{} (proto {})",
        src_ip, src_port, dst_ip, dst_port, tuple.proto
    );
    Ok(flow)
}

pub fn uninstall_drop_flow(port_id: u16, flow: *mut rte_flow) -> Result<()> {
    if flow.is_null() {
        println!("No flow to uninstall on port {}", port_id);
        return Ok(());
    }

    let mut error: rte_flow_error = unsafe { std::mem::zeroed() };

    let ret = unsafe { rte_flow_destroy(port_id, flow, &mut error) };

    if ret != 0 {
        let msg = unsafe {
            CStr::from_ptr(error.message)
                .to_string_lossy()
                .into_owned()
        };
        anyhow::bail!("Failed to uninstall flow on port {}: {}", port_id, msg);
    }

    println!("Uninstalled DROP rule on port {}", port_id);
    Ok(())
}