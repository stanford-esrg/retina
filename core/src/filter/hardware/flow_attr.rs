use crate::dpdk;
use std::mem;

/// An ingress flow attribute
pub(super) struct FlowAttribute(dpdk::rte_flow_attr);

impl FlowAttribute {
    pub(super) fn new(group: u32, priority: u32) -> Self {
        let mut attr: dpdk::rte_flow_attr = unsafe { mem::zeroed() };
        attr.set_ingress(1);
        attr.group = group;
        attr.priority = priority;
        FlowAttribute(attr)
    }

    /// Returns a reference to the inner rte_flow_attr for use with DPDK functions.
    pub(super) fn raw(&self) -> &dpdk::rte_flow_attr {
        &self.0
    }
}
