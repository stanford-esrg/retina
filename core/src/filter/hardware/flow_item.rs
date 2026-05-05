use crate::dpdk;

use crate::filter::ast::*;
use crate::filter::pattern::LayeredPattern;
use crate::filter::FilterError;

use std::ffi::c_void;

use std::convert::TryFrom;
use std::mem;

use anyhow::{bail, Result};

pub(super) trait FlowItemType {}

impl FlowItemType for dpdk::rte_flow_item_ipv4 {}
impl FlowItemType for dpdk::rte_flow_item_ipv6 {}
impl FlowItemType for dpdk::rte_flow_item_tcp {}
impl FlowItemType for dpdk::rte_flow_item_udp {}

pub(super) trait AnyFlowItem {
    fn item_type(&self) -> dpdk::rte_flow_item_type;
    fn spec(&self) -> *const c_void;
    fn mask(&self) -> *const c_void;
}

pub(super) struct FlowItem<T> {
    item_type: dpdk::rte_flow_item_type,
    spec: T,
    mask: T,
}

impl<T: FlowItemType> AnyFlowItem for FlowItem<T> {
    fn item_type(&self) -> dpdk::rte_flow_item_type {
        self.item_type
    }

    fn spec(&self) -> *const c_void {
        &self.spec as *const _ as *const c_void
    }

    fn mask(&self) -> *const c_void {
        &self.mask as *const _ as *const c_void
    }
}

pub(super) type PatternRules = Vec<dpdk::rte_flow_item>;

pub(super) fn append_eth(rules: &mut PatternRules) {
    let mut item: dpdk::rte_flow_item = unsafe { mem::zeroed() };
    item.type_ = dpdk::rte_flow_item_type_RTE_FLOW_ITEM_TYPE_ETH;
    rules.push(item);
}

pub(super) fn append_end(rules: &mut PatternRules) {
    let mut item: dpdk::rte_flow_item = unsafe { mem::zeroed() };
    item.type_ = dpdk::rte_flow_item_type_RTE_FLOW_ITEM_TYPE_END;
    rules.push(item);
}

pub(super) struct FlowPattern {
    pub(super) items: Vec<Box<dyn AnyFlowItem>>,
}

impl FlowPattern {
    pub(super) fn from_layered_pattern(pattern: &LayeredPattern) -> Result<FlowPattern> {
        let mut flow_pattern = FlowPattern { items: Vec::new() };

        for (protocol, field_preds) in pattern.get_header_predicates().iter() {
            match protocol.name() {
                "ipv4" => flow_pattern.append_ipv4(field_preds)?,
                "ipv6" => flow_pattern.append_ipv6(field_preds)?,
                "tcp" => flow_pattern.append_tcp(field_preds)?,
                "udp" => flow_pattern.append_udp(field_preds)?,
                _ => bail!(FilterError::InvalidHeader(protocol.name().to_owned())),
            }
        }
        Ok(flow_pattern)
    }

    pub(super) fn append_ipv4(&mut self, predicates: &[Predicate]) -> Result<()> {
        let mut ipv4_spec: dpdk::rte_flow_item_ipv4 = unsafe { mem::zeroed() };
        let mut ipv4_mask: dpdk::rte_flow_item_ipv4 = unsafe { mem::zeroed() };

        for pred in predicates.iter() {
            match pred {
                Predicate::Unary { .. } => bail!(FilterError::InvalidPredType("unary".to_owned())),
                Predicate::Binary {
                    protocol: _,
                    field,
                    op: _,
                    value,
                } => match field.name() {
                    "version_ihl" => match value {
                        Value::Int(i) => {
                            if let Ok(val) = u8::try_from(*i) {
                                ipv4_spec.hdr.version_ihl = val;
                                ipv4_mask.hdr.version_ihl = u8::MAX;
                            } else {
                                bail!(FilterError::InvalidRhsValue(value.to_string()))
                            }
                        }
                        _ => bail!(FilterError::InvalidRhsType(value.to_string())),
                    },
                    "type_of_service" => match value {
                        Value::Int(i) => {
                            if let Ok(val) = u8::try_from(*i) {
                                ipv4_spec.hdr.type_of_service = val;
                                ipv4_mask.hdr.type_of_service = u8::MAX;
                            } else {
                                bail!(FilterError::InvalidRhsValue(value.to_string()))
                            }
                        }
                        _ => bail!(FilterError::InvalidRhsType(value.to_string())),
                    },
                    "total_length" => match value {
                        Value::Int(i) => {
                            if let Ok(val) = u16::try_from(*i) {
                                ipv4_spec.hdr.total_length = val.to_be();
                                ipv4_mask.hdr.total_length = u16::MAX;
                            } else {
                                bail!(FilterError::InvalidRhsValue(value.to_string()))
                            }
                        }
                        _ => bail!(FilterError::InvalidRhsType(value.to_string())),
                    },
                    "identification" => match value {
                        Value::Int(i) => {
                            if let Ok(val) = u16::try_from(*i) {
                                ipv4_spec.hdr.packet_id = val.to_be();
                                ipv4_mask.hdr.packet_id = u16::MAX;
                            } else {
                                bail!(FilterError::InvalidRhsValue(value.to_string()))
                            }
                        }
                        _ => bail!(FilterError::InvalidRhsType(value.to_string())),
                    },
                    "flags_to_fragment_offset" => match value {
                        Value::Int(i) => {
                            if let Ok(val) = u16::try_from(*i) {
                                ipv4_spec.hdr.fragment_offset = val.to_be();
                                ipv4_mask.hdr.fragment_offset = u16::MAX;
                            } else {
                                bail!(FilterError::InvalidRhsValue(value.to_string()))
                            }
                        }
                        _ => bail!(FilterError::InvalidRhsType(value.to_string())),
                    },
                    "time_to_live" => match value {
                        Value::Int(i) => {
                            if let Ok(val) = u8::try_from(*i) {
                                ipv4_spec.hdr.time_to_live = val;
                                ipv4_mask.hdr.time_to_live = u8::MAX;
                            } else {
                                bail!(FilterError::InvalidRhsValue(value.to_string()))
                            }
                        }
                        _ => bail!(FilterError::InvalidRhsType(value.to_string())),
                    },
                    "protocol" => match value {
                        Value::Int(i) => {
                            if let Ok(val) = u8::try_from(*i) {
                                ipv4_spec.hdr.next_proto_id = val;
                                ipv4_mask.hdr.next_proto_id = u8::MAX;
                            } else {
                                bail!(FilterError::InvalidRhsValue(value.to_string()))
                            }
                        }
                        _ => bail!(FilterError::InvalidRhsType(value.to_string())),
                    },
                    "header_checksum" => match value {
                        Value::Int(i) => {
                            if let Ok(val) = u16::try_from(*i) {
                                ipv4_spec.hdr.hdr_checksum = val.to_be();
                                ipv4_mask.hdr.hdr_checksum = u16::MAX;
                            } else {
                                bail!(FilterError::InvalidRhsValue(value.to_string()))
                            }
                        }
                        _ => bail!(FilterError::InvalidRhsType(value.to_string())),
                    },
                    "src_addr" => match value {
                        Value::Ipv4(ipv4net) => {
                            ipv4_spec.hdr.src_addr = u32::from(ipv4net.addr()).to_be();
                            ipv4_mask.hdr.src_addr = u32::from(ipv4net.netmask()).to_be();
                        }
                        _ => bail!(FilterError::InvalidRhsType(value.to_string())),
                    },
                    "dst_addr" => match value {
                        Value::Ipv4(ipv4net) => {
                            ipv4_spec.hdr.dst_addr = u32::from(ipv4net.addr()).to_be();
                            ipv4_mask.hdr.dst_addr = u32::from(ipv4net.netmask()).to_be();
                        }
                        _ => bail!(FilterError::InvalidRhsType(value.to_string())),
                    },
                    _ => bail!(FilterError::InvalidField(field.name().to_owned())),
                },
            }
        }

        let ipv4_item = FlowItem::<dpdk::rte_flow_item_ipv4> {
            item_type: dpdk::rte_flow_item_type_RTE_FLOW_ITEM_TYPE_IPV4,
            spec: ipv4_spec,
            mask: ipv4_mask,
        };
        self.items.push(Box::new(ipv4_item));
        Ok(())
    }

    pub(super) fn append_ipv6(&mut self, predicates: &[Predicate]) -> Result<()> {
        let mut ipv6_spec: dpdk::rte_flow_item_ipv6 = unsafe { mem::zeroed() };
        let mut ipv6_mask: dpdk::rte_flow_item_ipv6 = unsafe { mem::zeroed() };

        for pred in predicates.iter() {
            match pred {
                Predicate::Unary { .. } => bail!(FilterError::InvalidPredType("unary".to_owned())),
                Predicate::Binary {
                    protocol: _,
                    field,
                    op: _,
                    value,
                } => match field.name() {
                    "version_to_flow_label" => match value {
                        Value::Int(i) => {
                            if let Ok(val) = u32::try_from(*i) {
                                ipv6_spec.hdr.vtc_flow = val.to_be();
                                ipv6_mask.hdr.vtc_flow = u32::MAX;
                            } else {
                                bail!(FilterError::InvalidRhsValue(value.to_string()))
                            }
                        }
                        _ => bail!(FilterError::InvalidRhsType(value.to_string())),
                    },
                    "payload_length" => match value {
                        Value::Int(i) => {
                            if let Ok(val) = u16::try_from(*i) {
                                ipv6_spec.hdr.payload_len = val.to_be();
                                ipv6_mask.hdr.payload_len = u16::MAX;
                            } else {
                                bail!(FilterError::InvalidRhsValue(value.to_string()))
                            }
                        }
                        _ => bail!(FilterError::InvalidRhsType(value.to_string())),
                    },
                    "next_header" => match value {
                        Value::Int(i) => {
                            if let Ok(val) = u8::try_from(*i) {
                                ipv6_spec.hdr.proto = val;
                                ipv6_mask.hdr.proto = u8::MAX;
                            } else {
                                bail!(FilterError::InvalidRhsValue(value.to_string()))
                            }
                        }
                        _ => bail!(FilterError::InvalidRhsType(value.to_string())),
                    },
                    "hop_limit" => match value {
                        Value::Int(i) => {
                            if let Ok(val) = u8::try_from(*i) {
                                ipv6_spec.hdr.hop_limits = val;
                                ipv6_mask.hdr.hop_limits = u8::MAX;
                            } else {
                                bail!(FilterError::InvalidRhsValue(value.to_string()))
                            }
                        }
                        _ => bail!(FilterError::InvalidRhsType(value.to_string())),
                    },
                    "src_addr" => match value {
                        Value::Ipv6(ipv6net) => {
                            ipv6_spec.hdr.src_addr = u128::from(ipv6net.addr()).to_be_bytes();
                            ipv6_mask.hdr.src_addr = u128::from(ipv6net.netmask()).to_be_bytes();
                        }
                        _ => bail!(FilterError::InvalidRhsType(value.to_string())),
                    },
                    "dst_addr" => match value {
                        Value::Ipv6(ipv6net) => {
                            ipv6_spec.hdr.dst_addr = u128::from(ipv6net.addr()).to_be_bytes();
                            ipv6_mask.hdr.dst_addr = u128::from(ipv6net.netmask()).to_be_bytes();
                        }
                        _ => bail!(FilterError::InvalidRhsType(value.to_string())),
                    },
                    _ => bail!(FilterError::InvalidField(field.name().to_owned())),
                },
            }
        }

        let ipv6_item = FlowItem::<dpdk::rte_flow_item_ipv6> {
            item_type: dpdk::rte_flow_item_type_RTE_FLOW_ITEM_TYPE_IPV6,
            spec: ipv6_spec,
            mask: ipv6_mask,
        };
        self.items.push(Box::new(ipv6_item));
        Ok(())
    }

    pub(super) fn append_tcp(&mut self, predicates: &[Predicate]) -> Result<()> {
        let mut tcp_spec: dpdk::rte_flow_item_tcp = unsafe { mem::zeroed() };
        let mut tcp_mask: dpdk::rte_flow_item_tcp = unsafe { mem::zeroed() };

        for pred in predicates.iter() {
            match pred {
                Predicate::Unary { .. } => bail!(FilterError::InvalidPredType("unary".to_owned())),
                Predicate::Binary {
                    protocol: _,
                    field,
                    op: _,
                    value,
                } => match field.name() {
                    "src_port" => match value {
                        Value::Int(i) => {
                            if let Ok(val) = u16::try_from(*i) {
                                tcp_spec.hdr.src_port = val.to_be();
                                tcp_mask.hdr.src_port = u16::MAX;
                            } else {
                                bail!(FilterError::InvalidRhsValue(value.to_string()))
                            }
                        }
                        _ => bail!(FilterError::InvalidRhsType(value.to_string())),
                    },
                    "dst_port" => match value {
                        Value::Int(i) => {
                            if let Ok(val) = u16::try_from(*i) {
                                tcp_spec.hdr.dst_port = val.to_be();
                                tcp_mask.hdr.dst_port = u16::MAX;
                            } else {
                                bail!(FilterError::InvalidRhsValue(value.to_string()))
                            }
                        }
                        _ => bail!(FilterError::InvalidRhsType(value.to_string())),
                    },
                    "seq_no" => match value {
                        Value::Int(i) => {
                            if let Ok(val) = u32::try_from(*i) {
                                tcp_spec.hdr.sent_seq = val.to_be();
                                tcp_mask.hdr.sent_seq = u32::MAX;
                            } else {
                                bail!(FilterError::InvalidRhsValue(value.to_string()))
                            }
                            tcp_spec.hdr.sent_seq = u32::try_from(*i).unwrap().to_be();
                            tcp_mask.hdr.sent_seq = u32::MAX;
                        }
                        _ => bail!(FilterError::InvalidRhsType(value.to_string())),
                    },
                    "ack_no" => match value {
                        Value::Int(i) => {
                            if let Ok(val) = u32::try_from(*i) {
                                tcp_spec.hdr.recv_ack = val.to_be();
                                tcp_mask.hdr.recv_ack = u32::MAX;
                            } else {
                                bail!(FilterError::InvalidRhsValue(value.to_string()))
                            }
                        }
                        _ => bail!(FilterError::InvalidRhsType(value.to_string())),
                    },
                    "data_offset_to_nw" => match value {
                        Value::Int(i) => {
                            if let Ok(val) = u8::try_from(*i) {
                                tcp_spec.hdr.data_off = val;
                                tcp_mask.hdr.data_off = u8::MAX;
                            } else {
                                bail!(FilterError::InvalidRhsValue(value.to_string()))
                            }
                        }
                        _ => bail!(FilterError::InvalidRhsType(value.to_string())),
                    },
                    "flags" => match value {
                        Value::Int(i) => {
                            if let Ok(val) = u8::try_from(*i) {
                                tcp_spec.hdr.tcp_flags = val;
                                tcp_mask.hdr.tcp_flags = u8::MAX;
                            } else {
                                bail!(FilterError::InvalidRhsValue(value.to_string()))
                            }
                        }
                        _ => bail!(FilterError::InvalidRhsType(value.to_string())),
                    },
                    "window" => match value {
                        Value::Int(i) => {
                            if let Ok(val) = u16::try_from(*i) {
                                tcp_spec.hdr.rx_win = val.to_be();
                                tcp_mask.hdr.rx_win = u16::MAX;
                            } else {
                                bail!(FilterError::InvalidRhsValue(value.to_string()))
                            }
                        }
                        _ => bail!(FilterError::InvalidRhsType(value.to_string())),
                    },
                    "checksum" => match value {
                        Value::Int(i) => {
                            if let Ok(val) = u16::try_from(*i) {
                                tcp_spec.hdr.cksum = val.to_be();
                                tcp_mask.hdr.cksum = u16::MAX;
                            } else {
                                bail!(FilterError::InvalidRhsValue(value.to_string()))
                            }
                        }
                        _ => bail!(FilterError::InvalidRhsType(value.to_string())),
                    },
                    "urgent_pointer" => match value {
                        Value::Int(i) => {
                            if let Ok(val) = u16::try_from(*i) {
                                tcp_spec.hdr.tcp_urp = val.to_be();
                                tcp_mask.hdr.tcp_urp = u16::MAX;
                            } else {
                                bail!(FilterError::InvalidRhsValue(value.to_string()))
                            }
                        }
                        _ => bail!(FilterError::InvalidRhsType(value.to_string())),
                    },
                    _ => bail!(FilterError::InvalidField(field.name().to_owned())),
                },
            }
        }

        let tcp_item = FlowItem::<dpdk::rte_flow_item_tcp> {
            item_type: dpdk::rte_flow_item_type_RTE_FLOW_ITEM_TYPE_TCP,
            spec: tcp_spec,
            mask: tcp_mask,
        };
        self.items.push(Box::new(tcp_item));
        Ok(())
    }

    pub(super) fn append_udp(&mut self, predicates: &[Predicate]) -> Result<()> {
        let mut udp_spec: dpdk::rte_flow_item_udp = unsafe { mem::zeroed() };
        let mut udp_mask: dpdk::rte_flow_item_udp = unsafe { mem::zeroed() };

        for pred in predicates.iter() {
            match pred {
                Predicate::Unary { .. } => bail!(FilterError::InvalidPredType("unary".to_owned())),
                Predicate::Binary {
                    protocol: _,
                    field,
                    op: _,
                    value,
                } => match field.name() {
                    "src_port" => match value {
                        Value::Int(i) => {
                            if let Ok(val) = u16::try_from(*i) {
                                udp_spec.hdr.src_port = val.to_be();
                                udp_mask.hdr.src_port = u16::MAX;
                            } else {
                                bail!(FilterError::InvalidRhsValue(value.to_string()))
                            }
                        }
                        _ => bail!(FilterError::InvalidRhsType(value.to_string())),
                    },
                    "dst_port" => match value {
                        Value::Int(i) => {
                            if let Ok(val) = u16::try_from(*i) {
                                udp_spec.hdr.dst_port = val.to_be();
                                udp_mask.hdr.dst_port = u16::MAX;
                            } else {
                                bail!(FilterError::InvalidRhsValue(value.to_string()))
                            }
                        }
                        _ => bail!(FilterError::InvalidRhsType(value.to_string())),
                    },
                    "length" => match value {
                        Value::Int(i) => {
                            if let Ok(val) = u16::try_from(*i) {
                                udp_spec.hdr.dgram_len = val.to_be();
                                udp_mask.hdr.dgram_len = u16::MAX;
                            } else {
                                bail!(FilterError::InvalidRhsValue(value.to_string()))
                            }
                        }
                        _ => bail!(FilterError::InvalidRhsType(value.to_string())),
                    },
                    "checksum" => match value {
                        Value::Int(i) => {
                            if let Ok(val) = u16::try_from(*i) {
                                udp_spec.hdr.dgram_cksum = val.to_be();
                                udp_mask.hdr.dgram_cksum = u16::MAX;
                            } else {
                                bail!(FilterError::InvalidRhsValue(value.to_string()))
                            }
                        }
                        _ => bail!(FilterError::InvalidRhsType(value.to_string())),
                    },
                    _ => bail!(FilterError::InvalidField(field.name().to_owned())),
                },
            }
        }

        let udp_item = FlowItem::<dpdk::rte_flow_item_udp> {
            item_type: dpdk::rte_flow_item_type_RTE_FLOW_ITEM_TYPE_UDP,
            spec: udp_spec,
            mask: udp_mask,
        };
        self.items.push(Box::new(udp_item));
        Ok(())
    }
}
