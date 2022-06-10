use crate::dpdk;
use crate::port::{PortId, SYMMETRIC_RSS_KEY};

use std::mem;

pub(super) type ActionRules = Vec<dpdk::rte_flow_action>;

/// Builds a vector of rte_flow_action
// #[derive(Debug, Clone)]
pub(super) struct FlowAction {
    pub(super) rules: ActionRules,
    port_id: PortId,

    // The following vectors contain configurations [conf] for special action
    pub(super) rss: Vec<dpdk::rte_flow_action_rss>,
    pub(super) jump: Vec<dpdk::rte_flow_action_jump>,
    pub(super) mark: Vec<dpdk::rte_flow_action_mark>,
    // drop has no config
}

impl FlowAction {
    pub(super) fn new(port_id: PortId) -> FlowAction {
        FlowAction {
            rules: ActionRules::new(),
            port_id,
            rss: Vec::<dpdk::rte_flow_action_rss>::new(),
            jump: Vec::<dpdk::rte_flow_action_jump>::new(),
            #[allow(dead_code)]
            mark: Vec::<dpdk::rte_flow_action_mark>::new(),
        }
    }

    pub(super) fn finish(&mut self) {
        // Add END terminator
        let mut a_end: dpdk::rte_flow_action = unsafe { mem::zeroed() };
        a_end.type_ = dpdk::rte_flow_action_type_RTE_FLOW_ACTION_TYPE_END;
        self.rules.push(a_end);
    }

    pub(super) fn append_jump(&mut self, group: u32) {
        let mut a_jump: dpdk::rte_flow_action = unsafe { mem::zeroed() };
        a_jump.type_ = dpdk::rte_flow_action_type_RTE_FLOW_ACTION_TYPE_JUMP;
        self.rules.push(a_jump);

        let mut jump_conf: dpdk::rte_flow_action_jump = unsafe { mem::zeroed() };
        jump_conf.group = group;

        self.jump.push(jump_conf);
    }

    #[allow(dead_code)]
    pub(super) fn append_mark(&mut self, mark: u32) {
        let mut a_mark: dpdk::rte_flow_action = unsafe { mem::zeroed() };
        a_mark.type_ = dpdk::rte_flow_action_type_RTE_FLOW_ACTION_TYPE_MARK;
        self.rules.push(a_mark);

        let mut mark_conf: dpdk::rte_flow_action_mark = unsafe { mem::zeroed() };
        mark_conf.id = mark;

        self.mark.push(mark_conf);
    }

    pub(super) fn append_rss(&mut self) {
        let mut a_rss: dpdk::rte_flow_action = unsafe { mem::zeroed() };
        a_rss.type_ = dpdk::rte_flow_action_type_RTE_FLOW_ACTION_TYPE_RSS;
        self.rules.push(a_rss);

        let mut rss_conf: dpdk::rte_eth_rss_conf = unsafe { mem::zeroed() };
        let ret = unsafe { dpdk::rte_eth_dev_rss_hash_conf_get(self.port_id.raw(), &mut rss_conf) };
        assert_eq!(ret, 0);

        let mut a_rss_conf: dpdk::rte_flow_action_rss = unsafe { mem::zeroed() };
        a_rss_conf.func = dpdk::rte_eth_hash_function_RTE_ETH_HASH_FUNCTION_TOEPLITZ;
        // Innermost encapsulation level PMD can handle
        a_rss_conf.level = 0;
        a_rss_conf.types = rss_conf.rss_hf;
        a_rss_conf.key_len = rss_conf.rss_key_len as u32;

        // Since the RSS key needs to outlive this method, we use the static
        // SYMMETRIC_RSS_KEY instead of the key queried from the existing rss_conf
        a_rss_conf.key = SYMMETRIC_RSS_KEY.as_ptr() as *const u8;

        self.rss.push(a_rss_conf);
    }

    #[allow(dead_code)]
    pub(super) fn append_drop(&mut self) {
        let mut a_drop: dpdk::rte_flow_action = unsafe { mem::zeroed() };
        a_drop.type_ = dpdk::rte_flow_action_type_RTE_FLOW_ACTION_TYPE_DROP;
        self.rules.push(a_drop);
    }
}
