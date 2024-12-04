use super::actions::*;
use super::ast::*;
use super::pattern::{FlatPattern, LayeredPattern};
use super::{Level, SubscriptionSpec};

use std::cmp::{Ordering, PartialOrd};
use std::collections::HashSet;
use std::fmt;

#[derive(Debug, Clone, Copy)]
pub enum FilterLayer {
    // Quick-pass filter per-packet
    PacketContinue,
    // Packet delivery | packet filter
    Packet,
    // Connection (protocol) filter
    Protocol,
    // Session delivery | session filter
    Session,
    // Connection delivery (conn. termination)
    ConnectionDeliver,
    // Packet delivery (packet datatype match at later layer)
    PacketDeliver,
}

impl fmt::Display for FilterLayer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FilterLayer::PacketContinue => write!(f, "Pkt (pass)"),
            FilterLayer::Packet => write!(f, "Pkt"),
            FilterLayer::Protocol => write!(f, "Proto"),
            FilterLayer::Session => write!(f, "S"),
            FilterLayer::ConnectionDeliver => write!(f, "C (D)"),
            FilterLayer::PacketDeliver => write!(f, "Pkt (D)"),
        }
    }
}

// Represents a subscription (callback, datatype)
// that will be delivered at a given filter node.
// Used in compile-time filter generation.
#[derive(Hash, Debug, Clone, PartialEq, Eq)]
pub struct Deliver {
    // Subscription ID as given by filtergen module
    pub id: usize,
    // Subscription spec formatted as CB(datatypes)
    pub as_str: String,
    // This callback should not be optimized out
    pub must_deliver: bool,
}

// A node representing a predicate in the tree
#[derive(Debug, Clone)]
pub struct PNode {
    // ID of node
    pub id: usize,

    // Predicate represented by this PNode
    pub pred: Predicate,

    // Actions to apply at this node
    // [for action filters]
    pub actions: Actions,

    // Subscriptions to deliver, by index, at this node
    // Empty for non-delivery filters.
    pub deliver: HashSet<Deliver>,

    // The patterns for which the predicate is a part of
    pub patterns: Vec<usize>,

    // Child PNodes
    pub children: Vec<PNode>,

    // Mutually exclusive with the node preceding it in child list
    pub if_else: bool,
}

impl PNode {
    fn new(pred: Predicate, id: usize) -> Self {
        PNode {
            id,
            pred,
            actions: Actions::new(),
            deliver: HashSet::new(),
            patterns: vec![],
            children: vec![],
            if_else: false,
        }
    }

    // Utility to check whether a descendant exists
    // Helper for `get_descendant`, which must be invoked in an `if` block
    // due to borrow checker
    fn has_descendant(&self, pred: &Predicate) -> bool {
        for n in &self.children {
            if &n.pred == pred {
                return true;
            }
            if pred.is_child(&n.pred) && n.has_descendant(pred) {
                return true;
            }
        }
        false
    }

    // See above
    fn get_descendant(&mut self, pred: &Predicate) -> Option<&mut PNode> {
        for n in &mut self.children {
            // found exact match
            if &n.pred == pred {
                return Some(n);
            }
            // node is a parent - keep descending
            if pred.is_child(&n.pred) {
                if let Some(c) = n.get_descendant(pred) {
                    return Some(c);
                }
            }
        }
        None
    }

    // Returns true if `self` has `pred` as a direct child
    fn has_child(&self, pred: &Predicate) -> bool {
        self.children.iter().any(|n| &n.pred == pred)
    }

    // See above
    fn get_child(&mut self, pred: &Predicate) -> &mut PNode {
        self.children.iter_mut().find(|n| &n.pred == pred).unwrap()
    }

    // True if `self` has children that should be (more specific)
    // children of `pred`
    fn has_children_of(&self, pred: &Predicate) -> bool {
        self.children.iter().any(|n| n.pred.is_child(pred))
    }

    // Returns all of the PNodes that should be children of `pred`,
    // while retaining in `self.children` the nodes that are
    // not children of `pred`
    fn get_children_of(&mut self, pred: &Predicate) -> Vec<PNode> {
        let new;
        let children = std::mem::take(&mut self.children);

        (new, self.children) = children.into_iter().partition(|p| p.pred.is_child(pred));

        new
    }

    // Returns a reference to a PNode that is a child of `self`
    // that can act as "parent" of `pred`.
    fn get_parent_candidate(&mut self, pred: &Predicate) -> Option<&mut PNode> {
        self.children.iter_mut().find(|n| pred.is_child(&n.pred))
    }

    // Returns true if (1) both `self` and `peer` have equal node-to-leaf paths
    // and (2) actions/CB are the same.
    // This is useful for marking nodes as mutually exclusive even
    // if there predicates are not mutually exclusive.
    fn outcome_eq(&self, peer: &PNode) -> bool {
        if self.actions != peer.actions || self.deliver != peer.deliver {
            return false;
        }
        (self.children.is_empty() && peer.children.is_empty()) || self.all_paths_eq(peer)
    }

    // True if there is a PNode that can act as parent of `pred`.
    fn has_parent(&self, pred: &Predicate) -> bool {
        for n in &self.children {
            if pred.is_child(&n.pred) {
                return true;
            }
        }
        false
    }

    // Returns a node that can act as a parent to `pred`, or None.
    // The most "narrow" parent condition will be returned if multiple exist.
    fn get_parent(&mut self, pred: &Predicate, tree_size: usize) -> Option<&mut PNode> {
        // This is messy, but directly iterating through children or
        // recursing will raise flags with the borrow checker.
        let mut node = self;
        for _ in 0..tree_size {
            // Checked for `Some` on last iteration
            let next = node.get_parent_candidate(pred)?;
            if next.get_parent_candidate(pred).is_none() {
                // `next` is the last possible parent at this stage
                return Some(next);
            } else {
                // There are more potential parents
                node = next;
            }
        }
        None
    }

    // Returns `true` if a condition cannot be removed from the filter due to
    // its role extracting data needed for a subsequent condition.
    // For example, getting `ipv4` is necessary for checking `ipv4.src_addr`.
    fn extracts_protocol(&self, filter_layer: FilterLayer) -> bool {
        // Filters that parse raw packets are special case
        // Need upper layers to extract inner from mbuf
        // E.g.: need ipv4 header to parse tcp
        if matches!(
            filter_layer,
            FilterLayer::PacketDeliver | FilterLayer::Packet
        ) && self.pred.is_unary()
            && self.children.iter().any(|n| n.pred.is_unary())
        {
            return true;
        }
        self.pred.is_unary()
            && self
                .children
                .iter()
                .any(|n| self.pred.get_protocol() == n.pred.get_protocol() && n.pred.is_binary())
    }

    // Populates `paths` will all root-to-leaf paths originating
    // at node `self`.
    fn get_paths(&self, curr_path: &mut Vec<String>, paths: &mut Vec<String>) {
        if self.children.is_empty() && !curr_path.is_empty() {
            paths.push(curr_path.join(","));
        } else {
            for c in &self.children {
                curr_path.push(format!("{}", c));
                c.get_paths(curr_path, paths);
            }
        }
        curr_path.pop();
    }

    fn all_paths_eq(&self, other: &PNode) -> bool {
        if self.children.is_empty() && other.children.is_empty() {
            return true;
        }
        let mut paths = vec![];
        let mut curr = vec![];
        self.get_paths(&mut curr, &mut paths);
        let mut peer_paths = vec![];
        curr = vec![];
        other.get_paths(&mut curr, &mut peer_paths);
        peer_paths == paths
    }
}

impl fmt::Display for PNode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.pred)?;
        if !self.actions.drop() {
            write!(f, " -- A: {:?}", self.actions)?;
        }
        if !self.deliver.is_empty() {
            write!(f, " D: ")?;
            write!(f, "( ")?;
            for d in &self.deliver {
                write!(f, "{}, ", d.as_str)?;
            }
            write!(f, ")")?;
        }
        if self.if_else {
            write!(f, " x")?;
        }
        Ok(())
    }
}

// A n-ary tree representing a Filter.
// Paths from root to leaf represent a pattern for data to match.
// Filter returns action(s) or delivers data.
#[derive(Debug, Clone)]
pub struct PTree {
    // Root node
    pub root: PNode,

    // Number of nodes in tree
    pub size: usize,

    // Possible actions
    pub actions: Actions,

    // Which filter this PTree represents
    pub filter_layer: FilterLayer,

    // Has `collapse` been applied?
    // Use to ensure no filters are applied after `collapse`
    collapsed: bool,
}

impl PTree {
    pub fn new_empty(filter_layer: FilterLayer) -> Self {
        let pred = Predicate::Unary {
            protocol: protocol!("ethernet"),
        };
        Self {
            root: PNode::new(pred, 0),
            size: 1,
            actions: Actions::new(),
            filter_layer,
            collapsed: false,
        }
    }

    // Add a filter to an existing PTree
    // Applied for multiple subscriptions, when multiple actions
    // and/or delivery filters will be checked at the same stage
    pub fn add_filter(
        &mut self,
        patterns: &[FlatPattern],
        subscription: &SubscriptionSpec,
        deliver: &Deliver,
    ) {
        if self.collapsed {
            panic!("Cannot add filter to tree after collapsing");
        }
        if matches!(self.filter_layer, FilterLayer::PacketDeliver)
            && !matches!(subscription.level, Level::Packet)
        {
            return;
        }
        if matches!(self.filter_layer, FilterLayer::ConnectionDeliver)
            && !matches!(subscription.level, Level::Connection | Level::Static)
        {
            return;
        }
        self.build_tree(patterns, subscription, deliver);
    }

    // Add all given patterns (root-to-leaf paths) to a PTree
    fn build_tree(
        &mut self,
        patterns: &[FlatPattern],
        subscription: &SubscriptionSpec,
        deliver: &Deliver,
    ) {
        // add each pattern to tree
        let mut added = false;
        for (i, pattern) in patterns.iter().enumerate() {
            if pattern.is_prev_layer(self.filter_layer, &subscription.level) {
                continue;
            }
            added = added || !pattern.predicates.is_empty();
            self.add_pattern(pattern, i, subscription, deliver);
        }

        if !added
            && self
                .root
                .pred
                .is_prev_layer(self.filter_layer, &subscription.level)
        {
            return;
        }

        // Need to terminate somewhere
        if !added {
            let pred = Predicate::default_pred();
            if subscription.should_deliver(self.filter_layer, &pred) {
                self.root.deliver.insert(deliver.clone());
            } else {
                let actions = subscription.with_term_filter(self.filter_layer, &pred);
                self.root.actions.push(&actions);
                self.actions.push(&actions);
            }
        }
    }

    // Add a single pattern (root-to-leaf path) to the tree.
    // Add nodes that don't exist. Update actions or subscription IDs
    // for terminal nodes at this stage.
    fn add_pattern(
        &mut self,
        pattern: &FlatPattern,
        pattern_id: usize,
        subscription: &SubscriptionSpec,
        deliver: &Deliver,
    ) {
        let mut node = &mut self.root;
        node.patterns.push(pattern_id);
        for predicate in pattern.predicates.iter() {
            // Next predicate shouldn't be processed;
            // node should be a non-terminal leaf node
            if predicate.is_next_layer(self.filter_layer) {
                let actions = subscription.with_nonterm_filter(self.filter_layer);
                node.actions.push(&actions);
                self.actions.push(&actions);
                // Stop descending - no terminal actions for this predicate
                return;
            }

            if !matches!(self.filter_layer, FilterLayer::PacketContinue) && predicate.req_packet() {
                // To get similar behavior, users should subscribe to individual mbufs or
                // the mbuf list, then filter within the callback.
                // Because (for now) all packets would need to be tracked anyway, doing this
                // is equivalent performance-wise to implementing similar functionality in the
                // framework.
                panic!("Cannot access per-packet fields (e.g., TCP flags, length) after packet filter.\n\
                       Subscribe to `ZcFrame` or list of mbufs instead.");
            }

            // Predicate is already present

            if node.has_descendant(predicate) {
                node = node.get_descendant(predicate).unwrap();
                node.patterns.push(pattern_id);
                continue;
            }

            // Predicate should be added as child of existing node
            if node.has_parent(predicate) {
                node = node.get_parent(predicate, self.size).unwrap();
            }

            // Children of curr node should be children of new node
            let children = match node.has_children_of(predicate) {
                true => node.get_children_of(predicate),
                false => {
                    vec![]
                }
            };

            // Create new node
            if !node.has_child(predicate) {
                node.children.push(PNode::new(predicate.clone(), self.size));
                self.size += 1;
            }
            // Move on, pushing any new children if applicable
            node = node.get_child(predicate);
            node.children.extend(children);
            node.patterns.push(pattern_id);
        }
        if subscription.should_deliver(self.filter_layer, &node.pred) {
            node.deliver.insert(deliver.clone());
        }
        let actions = subscription.with_term_filter(self.filter_layer, &node.pred);
        if !actions.drop() {
            node.actions.push(&actions);
            self.actions.push(&actions);
        }
    }

    // Returns a copy of the subtree rooted at Node `id`
    pub fn get_subtree(&self, id: usize) -> Option<PNode> {
        fn get_subtree(id: usize, node: &PNode) -> Option<PNode> {
            if node.id == id {
                return Some(node.clone());
            }
            for child in node.children.iter() {
                if let Some(node) = get_subtree(id, child) {
                    return Some(node);
                }
            }
            None
        }
        get_subtree(id, &self.root)
    }

    // Sorts the PTree according to predicates
    // Useful as a pre-step for marking mutual exclusion; places
    // conditions with the same protocols/fields next to each other.
    fn sort(&mut self) {
        fn sort(node: &mut PNode) {
            for child in node.children.iter_mut() {
                sort(child);
            }
            node.children.sort();
        }
        sort(&mut self.root);
    }

    // If only one callback is present in the tree, this function
    // returns it. Otherwise, it returns None.
    fn get_single_callback(&self) -> Option<Deliver> {
        fn check_callbacks(node: &PNode, callbacks: &mut HashSet<Deliver>) {
            if !node.deliver.is_empty() {
                callbacks.extend(node.deliver.iter().cloned());
            }
            if callbacks.len() > 1 {
                return;
            }
            for child in &node.children {
                check_callbacks(child, callbacks);
            }
        }
        let mut callbacks = HashSet::new();
        check_callbacks(&self.root, &mut callbacks);
        if callbacks.len() != 1 {
            return None;
        }
        Some(callbacks.iter().next().unwrap().clone())
    }

    // Remove all nodes and callbacks from the tree
    fn clear(&mut self) {
        let pred = Predicate::Unary {
            protocol: protocol!("ethernet"),
        };
        self.root = PNode::new(pred, 0);
        self.size = 1;
        self.actions = Actions::new();
        self.collapsed = false;
    }

    // Best-effort to give the filter generator hints as to where an "else"
    // statement can go between two predicates.
    fn mark_mutual_exclusion(&mut self) {
        fn mark_mutual_exclusion(node: &mut PNode) {
            for idx in 0..node.children.len() {
                // Recurse for children/descendants
                mark_mutual_exclusion(&mut node.children[idx]);
                if idx == 0 {
                    continue;
                }

                // Look for mutually exclusive predicates in direct children
                if node.children[idx]
                    .pred
                    .is_excl(&node.children[idx - 1].pred)
                {
                    node.children[idx].if_else = true;
                }
                // If the result is equivalent (e.g., same actions)
                // for child nodes, then we can safely use first match.
                // (Similar to "early return.")
                if node.children[idx].outcome_eq(&node.children[idx - 1]) {
                    node.children[idx].if_else = true;
                }
            }
        }
        mark_mutual_exclusion(&mut self.root);
    }

    // After collapsing the tree, make sure node IDs and sizes are correct.
    fn update_size(&mut self) {
        fn count_nodes(node: &mut PNode, id: &mut usize) -> usize {
            node.id = *id;
            *id += 1;
            let mut count = 1;
            for child in &mut node.children {
                count += count_nodes(child, id);
            }
            count
        }
        let mut id = 0;
        self.size = count_nodes(&mut self.root, &mut id);
    }

    // Removes some patterns that are covered by others
    fn prune_branches(&mut self) {
        fn prune(node: &mut PNode, on_path_actions: &Actions, on_path_deliver: &HashSet<String>) {
            // 1. Remove callbacks that would have already been invoked on this path
            let mut my_deliver = on_path_deliver.clone();
            let mut new_ids = HashSet::new();
            for i in &node.deliver {
                if !my_deliver.contains(&i.as_str) {
                    my_deliver.insert(i.as_str.clone());
                    new_ids.insert(i.clone());
                } else if i.must_deliver {
                    new_ids.insert(i.clone());
                }
            }
            node.deliver = new_ids;

            // 2. Remove actions that would have already been invoked on this path
            let mut my_actions = on_path_actions.clone();
            if !node.actions.drop() {
                node.actions.clear_intersection(&my_actions);
                my_actions.push(&node.actions);
            }

            // 3. Repeat for each child
            node.children
                .iter_mut()
                .for_each(|child| prune(child, &my_actions, &my_deliver));

            // 4. Remove empty children
            let children = std::mem::take(&mut node.children);
            node.children = children
                .into_iter()
                .filter(|child| {
                    !child.actions.drop() || !child.children.is_empty() || !child.deliver.is_empty()
                })
                .collect();
        }

        let on_path_actions = Actions::new();
        let on_path_deliver = HashSet::new();
        prune(&mut self.root, &on_path_actions, &on_path_deliver);
    }

    // Avoid re-checking packet-level conditions that, on the basis of previous
    // filters, are guaranteed to be already met.
    // For example, if all subscriptions filter for "tcp", then all non-tcp
    // connections will have been filtered out at the PacketContinue layer.
    // We only do this for packet-level conditions, as connection-level
    // conditions are needed to extract sessions.
    fn prune_packet_conditions(&mut self) {
        fn prune_packet_conditions(node: &mut PNode, filter_layer: FilterLayer, can_prune: bool) {
            if !node.pred.on_packet() {
                return;
            }
            // Can only safely remove children if
            // current branches are mutually exclusive
            let can_prune_next = node
                .children
                .windows(2)
                .all(|w| w[0].pred.is_excl(&w[1].pred));
            for child in &mut node.children {
                prune_packet_conditions(child, filter_layer, can_prune_next);
            }
            if !can_prune {
                return;
            }
            // Tree layer is only drop/keep (i.e., one condition),
            // and condition checked at prev. layer
            while node.children.len() == 1 && node.children[0].pred.on_packet() {
                // If the protocol needs to be extracted, can't remove node
                // Look for unary predicate (e.g., `ipv4`) and child with
                // binary predicate of same protocol (e.g., `ipv4.addr = ...`)
                let child = &mut node.children[0];
                if child.extracts_protocol(filter_layer) {
                    break;
                }
                node.actions.push(&child.actions);
                node.deliver.extend(child.deliver.iter().cloned());
                node.children = std::mem::take(&mut child.children);
            }
        }

        // Can't prune from the first filter
        // \Note future optimization could prune based on HW filtering if
        // confirmed that HW filtering will be enabled.
        if matches!(self.filter_layer, FilterLayer::PacketContinue) {
            return;
        }
        let can_prune_next = self
            .root
            .children
            .windows(2)
            .all(|w| w[0].pred.is_excl(&w[1].pred));
        prune_packet_conditions(&mut self.root, self.filter_layer, can_prune_next);
    }

    // Avoid applying conditions that (1) are not needed for filtering *out*
    // (i.e., would have already been checked by prev layer), and (2) end in
    // the same result.
    // Example: two different IP addresses in a packet filter followed by
    // a TCP/UDP disambiguation.
    fn prune_redundant_branches(&mut self) {
        fn prune_redundant_branches(node: &mut PNode, filter_layer: FilterLayer, can_prune: bool) {
            if !node.pred.is_prev_layer_pred(filter_layer) {
                return;
            }

            // Can only safely remove children if
            // current branches are mutually exclusive
            let can_prune_next = node
                .children
                .windows(2)
                .all(|w| w[0].pred.is_excl(&w[1].pred));

            for child in &mut node.children {
                prune_redundant_branches(child, filter_layer, can_prune_next);
            }
            if !can_prune {
                return;
            }

            let (must_keep, could_drop): (Vec<PNode>, Vec<PNode>) =
                node.children.iter().cloned().partition(|child| {
                    !child.actions.drop()
                        || !child.deliver.is_empty()
                        || !child.pred.is_prev_layer_pred(filter_layer)
                        || child.extracts_protocol(filter_layer)
                });
            let mut new_children = vec![];
            for child in &could_drop {
                // Can "upgrade" descendants if all children in a layer
                // have the same descendant conditions.
                if node.children.iter().all(|c| child.all_paths_eq(c)) {
                    new_children.extend(child.children.clone());
                } else {
                    new_children.push(child.clone());
                }
            }

            new_children.extend(must_keep);
            new_children.sort();
            new_children.dedup();
            node.children = new_children;
        }
        if matches!(self.filter_layer, FilterLayer::PacketContinue) {
            return;
        }
        let can_prune_next = self
            .root
            .children
            .windows(2)
            .all(|w| w[0].pred.is_excl(&w[1].pred));
        prune_redundant_branches(&mut self.root, self.filter_layer, can_prune_next);
    }

    // Apply all filter tree optimizations.
    // This must only be invoked AFTER the tree is completely built.
    pub fn collapse(&mut self) {
        if matches!(
            self.filter_layer,
            FilterLayer::PacketDeliver | FilterLayer::ConnectionDeliver
        ) {
            self.collapsed = true;

            // The delivery filter will only be invoked if a previous filter
            // determined that delivery is needed at the corresponding stage.
            // If disambiguation is not needed (i.e., only one possible delivery
            // outcome), then no filter condition is needed.
            if let Some(deliver) = self.get_single_callback() {
                self.clear();
                self.root.deliver.insert(deliver);
                self.update_size();
                return;
            }
        }
        self.prune_redundant_branches();
        self.prune_packet_conditions();
        self.prune_branches();
        self.sort();
        self.mark_mutual_exclusion(); // Must be last
        self.update_size();
    }

    pub fn to_flat_patterns(&self) -> Vec<FlatPattern> {
        fn build_pattern(
            patterns: &mut Vec<FlatPattern>,
            predicates: &mut Vec<Predicate>,
            node: &PNode,
        ) {
            if *node.pred.get_protocol() != protocol!("ethernet") {
                predicates.push(node.pred.to_owned());
            }
            if node.children.is_empty() {
                patterns.push(FlatPattern {
                    predicates: predicates.to_vec(),
                });
            } else {
                for child in node.children.iter() {
                    build_pattern(patterns, predicates, child);
                }
            }
            predicates.pop();
        }
        let mut patterns = vec![];
        let mut predicates = vec![];

        build_pattern(&mut patterns, &mut predicates, &self.root);
        patterns
    }

    #[allow(dead_code)]
    pub(crate) fn to_layered_patterns(&self) -> Vec<LayeredPattern> {
        let flat_patterns = self.to_flat_patterns();
        let mut layered = vec![];
        for pattern in flat_patterns.iter() {
            layered.extend(pattern.to_fully_qualified().expect("fully qualified"));
        }
        layered
    }

    // modified from https://vallentin.dev/2019/05/14/pretty-print-tree
    fn pprint(&self) -> String {
        fn pprint(s: &mut String, node: &PNode, prefix: String, last: bool) {
            let prefix_current = if last { "`- " } else { "|- " };

            let s_next = format!("{}{}{}: {}\n", prefix, prefix_current, node.id, node);
            s.push_str(&s_next);

            let prefix_child = if last { "   " } else { "|  " };
            let prefix = prefix + prefix_child;

            if !node.children.is_empty() {
                let last_child = node.children.len() - 1;

                for (i, child) in node.children.iter().enumerate() {
                    pprint(s, child, prefix.to_string(), i == last_child);
                }
            }
        }

        let mut s = String::new();
        pprint(&mut s, &self.root, "".to_string(), true);
        s
    }

    // Displays the conditions in the PTree as a filter string
    pub fn to_filter_string(&self) -> String {
        fn to_filter_string(p: &PNode, all: &mut Vec<String>, curr: String) {
            let mut curr = curr;
            if curr.is_empty() {
                curr.push('(');
            } else {
                curr.push_str(&format!("({})", p.pred));
            }
            if p.children.is_empty() {
                let mut path_str = curr.clone();
                path_str.push(')');
                all.push(path_str);
            } else {
                if curr != "(" {
                    curr.push_str(" and ");
                }
                for child in &p.children {
                    to_filter_string(child, all, curr.clone());
                }
            }
        }

        let mut all_filters = Vec::new();
        let curr_filter = String::new();
        if self.root.children.is_empty() {
            return "".into();
        }
        to_filter_string(&self.root, &mut all_filters, curr_filter);
        all_filters.join(" or ")
    }
}

impl fmt::Display for PTree {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Tree {}\n,{}", &self.filter_layer, self.pprint())?;
        Ok(())
    }
}

// Compares the contents of the nodes, ignoring children
// To consider children, use outcome_eq
impl PartialEq for PNode {
    fn eq(&self, other: &PNode) -> bool {
        self.pred == other.pred && self.actions == other.actions && self.deliver == other.deliver
    }
}

impl Eq for PNode {}

impl PartialOrd for PNode {
    fn partial_cmp(&self, other: &PNode) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

// Used for ordering nodes by protocol and field
// Does NOT consider contents of the node
impl Ord for PNode {
    fn cmp(&self, other: &PNode) -> Ordering {
        if let Predicate::Binary {
            protocol: proto,
            field: field_name,
            op: _op,
            value: _val,
        } = &self.pred
        {
            if let Predicate::Binary {
                protocol: peer_proto,
                field: peer_field_name,
                op: _peer_op,
                value: _peer_val,
            } = &other.pred
            {
                // Same protocol; sort fields
                if proto == peer_proto {
                    return field_name.name().cmp(peer_field_name.name());
                }
            }
        }

        // Sort by protocol name
        self.pred
            .get_protocol()
            .name()
            .cmp(other.pred.get_protocol().name())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::filter::*;

    lazy_static! {
        static ref DELIVER: Deliver = Deliver {
            id: 0,
            as_str: String::from("CB(X)"),
            must_deliver: false,
        };
    }

    #[test]
    fn core_ptree_session() {
        let datatype_conn = SubscriptionSpec::new_default_connection();
        let datatype_session = SubscriptionSpec::new_default_session();

        let filter = Filter::new("tls.sni = \'abc\'").unwrap();

        // Add Conn and Session-layer datatypes with Session-level filter
        let mut ptree = PTree::new_empty(FilterLayer::Session);
        ptree.add_filter(&filter.get_patterns_flat(), &datatype_conn, &DELIVER);
        ptree.add_filter(&filter.get_patterns_flat(), &datatype_session, &DELIVER);

        let mut expected_actions = Actions::new();
        expected_actions.data |=
            ActionData::UpdatePDU | ActionData::SessionTrack | ActionData::ConnDeliver;
        expected_actions.terminal_actions |= ActionData::UpdatePDU | ActionData::ConnDeliver;
        assert!(ptree.actions == expected_actions);
        assert!(!ptree.get_subtree(4).unwrap().deliver.is_empty());

        // Add filter that terminates at connection layer; should be no-op
        let noop_filter = Filter::new("tls").unwrap();
        ptree.add_filter(&noop_filter.get_patterns_flat(), &datatype_conn, &DELIVER);
        assert!(ptree.get_subtree(3).unwrap().actions.drop());
        // println!("{}", ptree);

        // Session ptree with "or" should exclude patterns that terminate at upper layers
        let filter =
            Filter::new("(ipv4 and tls.sni = \'abc\') or (ipv4.dst_addr = 1.1.1.1/32)").unwrap();
        let mut ptree: PTree = PTree::new_empty(FilterLayer::Session);
        ptree.add_filter(&filter.get_patterns_flat(), &datatype_conn, &DELIVER);
        assert!(ptree.size == 5); // eth - ipv4 - tls - tls sni
    }

    #[test]
    fn core_ptree_proto() {
        let mut expected_actions = Actions::new();

        let filter_conn = Filter::new("ipv4 and tls").unwrap();
        let datatype = SubscriptionSpec::new_default_connection();

        // Connection-level datatype matching at connection level
        let mut ptree = PTree::new_empty(FilterLayer::Protocol);
        ptree.add_filter(&filter_conn.get_patterns_flat(), &datatype, &DELIVER);
        expected_actions.data |= ActionData::UpdatePDU | ActionData::ConnDeliver;
        expected_actions.terminal_actions |= ActionData::UpdatePDU | ActionData::ConnDeliver;
        // println!("{}", ptree);
        assert!(ptree.actions == expected_actions);

        // Session-level datatype matching at session level
        let filter = Filter::new("ipv4 and tls.sni = \'abc\'").unwrap();
        let datatype = SubscriptionSpec::new_default_session();
        ptree.add_filter(&filter.get_patterns_flat(), &datatype, &DELIVER);
        expected_actions.data |= ActionData::SessionFilter;
        assert!(ptree.actions == expected_actions);

        // Session-level datatype matching at connection level
        let filter = Filter::new("ipv4 and http").unwrap();
        ptree.add_filter(&filter.get_patterns_flat(), &datatype, &DELIVER);
        expected_actions.data |= ActionData::SessionDeliver;
        // println!("{} {:?}", ptree, expected_actions);
        assert!(ptree.actions == expected_actions);
    }

    #[test]
    fn core_ptree_packet() {
        let mut expected_actions = Actions::new();
        let filter = Filter::new("ipv4 and tls").unwrap();
        let datatype = SubscriptionSpec::new_default_connection();
        let mut ptree = PTree::new_empty(FilterLayer::Packet);
        ptree.add_filter(&filter.get_patterns_flat(), &datatype, &DELIVER);

        expected_actions.data |= ActionData::ProtoFilter | ActionData::UpdatePDU;
        // println!("{}", ptree);
        assert!(ptree.actions == expected_actions);

        // Packet ptree should exclude patterns that terminate at lower layers
        let filter =
            Filter::new("ipv4.dst_addr = 1.1.1.1 or (ipv4 and tls) or (ipv4 and quic)").unwrap();
        let mut ptree = PTree::new_empty(FilterLayer::Packet);
        let datatype = SubscriptionSpec::new_default_packet();
        ptree.add_filter(&filter.get_patterns_flat(), &datatype, &DELIVER);
        ptree.collapse();
        // println!("{}", ptree);
        // ipv4.dst_addr should be prev. layer (delivered)
        // ipv4 still needed for protocol extraction
        // Remaining: eth -> tcp, udp
        assert!(ptree.size == 4);
        expected_actions.clear();
        expected_actions.data = ActionData::ProtoFilter | ActionData::PacketCache;
        assert!(ptree.actions == expected_actions);

        let mut ptree = PTree::new_empty(FilterLayer::PacketContinue);
        ptree.add_filter(&filter.get_patterns_flat(), &datatype, &DELIVER);
        // println!("{}", ptree);
        // Need to apply all conditions at first layer of packet filtering
        assert!(ptree.size == 5);
    }

    #[test]
    fn core_ptree_pkt_deliver() {
        let filter = Filter::new("ipv4 and tls").unwrap();
        let datatype = SubscriptionSpec::new_default_packet();
        let mut ptree = PTree::new_empty(FilterLayer::PacketDeliver);
        ptree.add_filter(&filter.get_patterns_flat(), &datatype, &DELIVER);
        assert!(!ptree.get_subtree(3).unwrap().deliver.is_empty());

        let mut ptree = PTree::new_empty(FilterLayer::Packet);
        ptree.add_filter(&filter.get_patterns_flat(), &datatype, &DELIVER);
        let mut expected_actions = Actions::new();
        expected_actions.data |= ActionData::PacketCache | ActionData::ProtoFilter;
        assert!(ptree.actions == expected_actions);
    }

    #[test]
    fn core_ptree_with_children() {
        let filter = "ipv4 and tls";
        // For packet filter, child of `filter`
        let filter_child1 = "ipv4.addr = 1.2.0.0/16 and http";

        // Child of child3 (added first)
        let filter_child2 = "ipv4.addr = 1.2.2.255/30";
        let filter_child3 = "ipv4.addr = 1.2.2.0/24";
        // Child of child3
        let filter_child4 = "ipv4.src_addr = 1.2.2.3/32";
        // Standalone filter
        let filter_child5 = "ipv4.src_addr = 1.3.3.1/32";

        let datatype_conn = SubscriptionSpec::new_default_connection();
        let datatype_session = SubscriptionSpec::new_default_session();

        let mut ptree = PTree::new_empty(FilterLayer::Packet);

        let mut deliver = DELIVER.clone();

        let filter = Filter::new(filter).unwrap();
        ptree.add_filter(&filter.get_patterns_flat(), &datatype_session, &deliver);
        let filter = Filter::new(filter_child1).unwrap();
        deliver.id = 1;
        ptree.add_filter(&filter.get_patterns_flat(), &datatype_session, &deliver);
        let filter = Filter::new(filter_child2).unwrap();
        deliver.id = 2;
        ptree.add_filter(&filter.get_patterns_flat(), &datatype_conn, &deliver);
        let filter: Filter = Filter::new(filter_child3).unwrap();
        deliver.id = 3;
        ptree.add_filter(&filter.get_patterns_flat(), &datatype_conn, &deliver);
        let filter = Filter::new(filter_child4).unwrap();
        deliver.id = 4;
        ptree.add_filter(&filter.get_patterns_flat(), &datatype_conn, &deliver);
        let filter = Filter::new(filter_child5).unwrap();
        deliver.id = 5;
        ptree.add_filter(&filter.get_patterns_flat(), &datatype_conn, &deliver);

        // no_op
        ptree.add_filter(&filter.get_patterns_flat(), &datatype_conn, &deliver);

        // println!("{}", ptree);
        assert!(ptree.size == 13);
        ptree.prune_branches();
        ptree.update_size();
        // println!("{}", ptree);
        assert!(ptree.size == 10);

        // ipv4.src_addr = 1.2.0.0/16
        let node = ptree.get_subtree(6).unwrap();
        // tcp (ProtoFilter), ipv4.src_addr = 1.2.2.0/24 (CData Track)
        assert!(node.children.len() == 2);

        // Should have been removed after pruning
        assert!(!ptree.to_filter_string().contains("1.2.2.3/32"));
        // Should not be in packet filter
        assert!(!ptree.to_filter_string().contains("http"));
    }

    #[test]
    fn deliver_ptree() {
        let filter = "ipv4.src_addr = 1.3.3.0/24";
        let filter_child = "ipv4.src_addr = 1.3.3.1/31";
        let datatype_conn = SubscriptionSpec::new_default_connection();

        let mut ptree = PTree::new_empty(FilterLayer::ConnectionDeliver);

        let mut deliver = DELIVER.clone();

        let filter = Filter::new(filter).unwrap();
        ptree.add_filter(&filter.get_patterns_flat(), &datatype_conn, &deliver);
        let filter = Filter::new(filter_child).unwrap();
        deliver.id = 1;
        ptree.add_filter(&filter.get_patterns_flat(), &datatype_conn, &deliver);

        ptree.prune_branches();
        ptree.update_size();
        assert!(!ptree.to_filter_string().contains("1.3.3.1/31") && ptree.size == 3);
        // eth, ipv4, ipvr.src
    }

    #[test]
    fn multi_ptree() {
        let filter_str = "ipv4 and http";
        let mut spec = SubscriptionSpec::new(String::from(filter_str), String::from("callback"));
        spec.add_datatype(DataType::new_default_connection("Connection"));
        spec.add_datatype(DataType::new_default_session("S", vec![]));

        let mut deliver = DELIVER.clone();

        let mut ptree = PTree::new_empty(FilterLayer::ConnectionDeliver);
        let filter = Filter::new(filter_str).unwrap();
        ptree.add_filter(&filter.get_patterns_flat(), &spec, &deliver);

        ptree.collapse();

        // One CB - no disambiguation needed in delivery filter
        assert!(ptree.size == 1 && !ptree.root.deliver.is_empty());

        // Two CBs - disambiguation needed
        ptree.clear();
        ptree.add_filter(&filter.get_patterns_flat(), &spec, &deliver);
        let mut spec_conn =
            SubscriptionSpec::new(String::from(filter_str), String::from("callback_conn"));
        spec_conn.add_datatype(DataType::new_default_connection("Connection"));
        deliver.id = 1;
        ptree.add_filter(&filter.get_patterns_flat(), &spec_conn, &deliver);

        // eth -> ipv4 -> tcp -> http
        assert!(ptree.size == 4);
        ptree.collapse();
        // ipv4 and tcp are removed (would have been filtered out by prev. filters)
        assert!(ptree.size == 2);

        // Packet FilterLayer
        let mut ptree = PTree::new_empty(FilterLayer::Packet);
        ptree.add_filter(&filter.get_patterns_flat(), &spec, &DELIVER);
        ptree.collapse();
        // Only one path (eth -> ipv4) would have already been applied at PacketContinue
        println!("{}", ptree);
        assert!(ptree.size == 1 && ptree.actions.data.contains(ActionData::UpdatePDU));

        ptree.clear();

        // Multiple paths: eth -> ipv4 -> [tcp, udp], ipv6 -> [udp]
        deliver.id = 0;
        ptree.add_filter(&filter.get_patterns_flat(), &spec, &deliver);
        let filter_str = "quic";
        let filter = Filter::new(filter_str).unwrap();
        deliver.id = 1;
        ptree.add_filter(&filter.get_patterns_flat(), &spec_conn, &deliver);
        assert!(ptree.size == 6);
    }

    #[test]
    fn core_ptree_prune() {
        let filters = vec![
            "ipv4.src_addr = 172.16.133.0 and (http)",
            "ipv4.dst_addr = 68.64.0.0 and (http)",
            "ipv4.src_addr = 172.16.133.0 and (quic)",
            "ipv4.dst_addr = 68.64.0.0 and (quic)",
            "ipv4.src_addr = 172.16.133.0 and (udp and dns)",
            "ipv4.dst_addr = 68.64.0.0 and (udp and dns)",
        ];
        let mut ptree = PTree::new_empty(FilterLayer::Packet);
        for f in &filters {
            let mut spec = SubscriptionSpec::new(String::from(*f), String::from("callback"));
            spec.add_datatype(DataType::new_default_connection("Connection"));
            spec.add_datatype(DataType::new_default_session("S", vec![]));
            let filter = Filter::new(f).unwrap();
            ptree.add_filter(&filter.get_patterns_flat(), &spec, &DELIVER);
        }
        assert!(ptree.size == 8);
        ptree.collapse();
        // IPv4 address disambiguation was removed, but `ipv4`
        // still needed to extract protocol.
        // eth -> ipv4 -> [tcp, udp]
        // println!("{}", ptree);
        assert!(ptree.size == 4);

        let mut ptree = PTree::new_empty(FilterLayer::Protocol);
        for f in &filters[0..filters.len() - 1] {
            let mut spec = SubscriptionSpec::new(String::from(*f), String::from("callback"));
            spec.add_datatype(DataType::new_default_connection("Connection"));
            spec.add_datatype(DataType::new_default_session("S", vec![]));
            let filter = Filter::new(f).unwrap();
            ptree.add_filter(&filter.get_patterns_flat(), &spec, &DELIVER);
        }

        // Can't remove IPs, because dns is no longer present under `68.64.0.0` --
        // need to disambiguate
        ptree.collapse();
        assert!(ptree.size == 13);

        let mut ptree = PTree::new_empty(FilterLayer::ConnectionDeliver);
        for f in &filters {
            let mut spec = SubscriptionSpec::new(String::from(*f), String::from("callback"));
            spec.add_datatype(DataType::new_default_connection("Connection"));
            spec.add_datatype(DataType::new_default_session("S", vec![]));
            let filter = Filter::new(f).unwrap();
            ptree.add_filter(&filter.get_patterns_flat(), &spec, &DELIVER);
        }

        ptree.collapse();
        // One subscription, no disambiguation
        assert!(ptree.size == 1);
    }

    #[test]
    fn core_ptree_neq() {
        let filters = vec![
            "tcp.dst_port != 80 and tcp.dst_port != 8080 and http",
            "dns and ((tcp and tcp.dst_port != 53 and tcp.dst_port != 5353) or (udp and udp.dst_port != 53 and udp.dst_port != 5353))",
        ];
        let mut ptree = PTree::new_empty(FilterLayer::Session);
        for f in &filters {
            let mut spec = SubscriptionSpec::new(String::from(*f), String::from("callback"));
            spec.add_datatype(DataType::new_default_session("S", vec![]));
            let filter = Filter::new(f).unwrap();
            ptree.add_filter(&filter.get_patterns_flat(), &spec, &DELIVER);
        }
        ptree.collapse();
        assert!(ptree.size == 10);
        // eth -> tcp -> tcp.dst_port != 80 -> tcp.dst_port != 8080
        // make sure tcp.dst_port != 8080 is still there
        assert!(ptree.get_subtree(2).unwrap().children.len() == 1);
    }

    #[test]
    fn core_parser_combined() {
        let filter = Filter::new("tcp.port != 80").unwrap();
        let filter_2 = Filter::new("ipv4.addr = 1.1.1.1").unwrap();
        let datatype_conn = SubscriptionSpec::new_default_connection();

        let mut ptree = PTree::new_empty(FilterLayer::PacketContinue);
        ptree.add_filter(&filter.get_patterns_flat(), &datatype_conn, &DELIVER);
        ptree.collapse();
        let mut ptree_2 = PTree::new_empty(FilterLayer::PacketContinue);
        ptree_2.add_filter(&filter_2.get_patterns_flat(), &datatype_conn, &DELIVER);
        ptree_2.collapse();

        assert!(
            // && conditions
            !ptree.get_subtree(3).unwrap().children.is_empty() &&
            // || conditions
            ptree_2.get_subtree(3).unwrap().children.is_empty()
        );
    }
}
