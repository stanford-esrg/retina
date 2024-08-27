use super::ast::*;
use super::pattern::{FlatPattern, LayeredPattern};
use super::actions::*;
use super::datatypes::{Level, DataType};

use std::fmt;
use std::collections::HashSet;
use std::cmp::{Ordering, PartialOrd};

#[derive(Debug, Clone, Copy)]
pub enum FilterLayer {
    // TODO revisit these

    /// Quick-pass filter per-packet 
    PacketContinue,
    /// Packet delivery | packet filter
    Packet,
    /// Connection (protocol) filter
    Protocol, 
    /// Session delivery | session filter
    Session,
    /// Connection delivery (conn. termination)
    ConnectionDeliver,
    /// Packet delivery (packet datatype match at later layer)
    PacketDeliver,
}

impl fmt::Display for FilterLayer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FilterLayer::PacketContinue => write!(f, "P (pass)"),
            FilterLayer::Packet => write!(f, "P"),
            FilterLayer::Protocol=> write!(f, "C"),
            FilterLayer::Session => write!(f, "S"),
            FilterLayer::ConnectionDeliver => write!(f, "C (D)"),
            FilterLayer::PacketDeliver => write!(f, "P (D)"),
        }
    }
}

#[derive(Hash, Debug, Clone, PartialEq, Eq)]
pub struct Deliver {
    pub id: usize,
    pub as_str: String,
}

/// A node representing a predicate in the tree
#[derive(Debug, Clone)]
pub struct PNode {
    /// ID of node
    pub id: usize,

    /// Predicate represented by this PNode
    pub pred: Predicate,

    /// Actions to apply at this node 
    /// [for action filters]
    pub actions: Actions,

    /// Subscriptions to deliver, by index, at this node
    /// Empty for non-delivery filters.
    pub deliver: HashSet<Deliver>,

    /// The patterns for which the predicate is a part of
    pub patterns: Vec<usize>,

    /// Child PNodes
    pub children: Vec<PNode>,

    /// Mutually exclusive with the node preceding it in child list
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
    // Need to actually get the descendant in an `if` block to make borrow checker happy
    fn has_descendant(&self, pred: &Predicate) -> bool {
        for n in &self.children {
            if &n.pred == pred { 
                return true;
            }
            if pred.is_child(&n.pred) {
                if n.has_descendant(pred) {
                    return true;
                }
            }
        }
        false
    }

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

    fn has_child(&self, pred: &Predicate) -> bool {
        self.children.iter().any(|n| &n.pred == pred)
    }

    fn get_child(&mut self, pred: &Predicate) -> &mut PNode {
        self.children.iter_mut().find(|n| &n.pred == pred).unwrap()
    }

    /// True if `self` has children that should be (more specific)
    /// children of `pred`
    fn has_children_of(&self, pred: &Predicate) -> bool {
        self.children.iter().any( |n| n.pred.is_child(pred))
    }

    fn get_children_of(&mut self, pred: &Predicate) -> Vec<PNode> {
        // drain_filter is unstable in current rust
        // better way to do this is swap indices then use `drain` at index
        /* 
        let mut children = self.children.clone();
        self.children.retain(|x| !x.pred.is_child(pred));
        children.retain(|x| x.pred.is_child(pred));
        children
         */
        let mut new = vec![];
        self.children = std::mem::take(&mut self.children).into_iter()
                                     .filter_map(|x| {
            if x.pred.is_child(pred) {
                new.push(x);
                None
            } else {
                Some(x)
            }
        }).collect();
        
        new
    }

    /// Returns a reference to a PNode that is a child of `self` 
    /// that can act as "parent" of `pred`. 
    fn get_parent_candidate(&mut self, pred: &Predicate) -> Option<&mut PNode> {
        self.children.iter_mut().find(|n | pred.is_child(&n.pred))
    }

    /// Returns true if (1) both are leaf nodes and (2) actions/CB are the same
    fn result_eq(&self, peer: &PNode) -> bool {
        if peer.children.len() > 0 || self.children.len() > 0 {
            return false; // TODO could recurse here 
        }

        self.actions == peer.actions && self.deliver == peer.deliver
    }

    /// True if there is a PNode that can act as parent of `pred`.
    fn has_parent(&self, pred: &Predicate) -> bool {
        let mut found = false;
        for n in &self.children {
            if pred.is_child(&n.pred) {
                if n.has_parent(pred) {
                    return true;
                } 
                found = true;
            }
        }
        return found;
    }

    fn get_parent(&mut self, pred: &Predicate, tree_size: usize) -> Option<&mut PNode> {
        if self.get_parent_candidate(pred).is_none() {
            return None;
        }
        // This is hacky, but directly iterating through children or 
        // recursing will raise flags with the borrow checker.
        let mut node = self;
        for _ in 0..tree_size {
            // Checked for `Some` on last iteration
            let next = node.get_parent_candidate(pred).unwrap();
            if next.get_parent_candidate(pred).is_none() {
                // `next` is the last possible parent at this stage
                return Some(next);
            } else {
                // there are more parents
                node = next;
            }
        }
        return None
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
            write!(f, " x")?; // todo better formatting
        }
        Ok(())
    }
}

/// \todo 
/// - This should be a BDD.
/// - There should be a better way to prune/parse here
///   to optimize for number of checks that are likely to be required.

/// A n-ary tree representing a Filter as applied by each lcore
/// to connection-level data.
/// Paths from root to leaf represent a pattern for data to match
/// on an action or subscription delivery.
#[derive(Debug, Clone)]
pub struct PTree {
    /// Root node
    pub root: PNode,

    /// Number of nodes in tree
    pub size: usize,

    /// Possible actions
    pub actions: Actions,

    /// Which filter this PTree represents
    pub filter_layer: FilterLayer,
}

impl PTree {

    pub fn new_empty(filter_layer: FilterLayer) -> Self {
        let pred = Predicate::Unary { protocol: protocol!("ethernet"), };
        let root = PNode::new(pred, 0); 
        let ptree = PTree { 
            root, 
            size: 1, 
            actions: Actions::new(),
            filter_layer 
        };
        ptree
    }

    /// Add a filter to an existing PTree
    /// Applied for multiple subscriptions, when multiple actions 
    /// and/or delivery filters will be checked at the same stage
    pub fn add_filter(&mut self, patterns: &[FlatPattern], 
                      datatype: &DataType, filter_id: usize, 
                      subscription_str: &String) {
        if matches!(self.filter_layer, FilterLayer::PacketDeliver) && 
           !matches!(datatype.level, Level::Packet) {
            return;
        }
        self.build_tree(patterns, datatype, filter_id, subscription_str);
    }

    /// Add all given patterns (root-to-leaf paths) to a PTree
    pub fn build_tree(&mut self, patterns: &[FlatPattern], 
                      datatype: &DataType, filter_id: usize,
                      subscription_str: &String) {
        // add each pattern to tree
        let mut added = false;
        for (i, pattern) in patterns.iter().enumerate() {
            added = added || !pattern.predicates.is_empty();
            self.add_pattern(pattern, i, datatype, filter_id, 
                             subscription_str);
        }

        // Need to terminate somewhere
        if !added {
            let pred = Predicate::default_pred();
            if datatype.should_deliver(self.filter_layer, &pred) {
                self.root.deliver.insert(Deliver { id: filter_id, as_str: subscription_str.clone()});
            } else {
                let actions = datatype.with_term_filter(self.filter_layer);
                self.root.actions.push(&actions);
                self.actions.push(&actions);
            }
        }
    }

    /// Add a single pattern (root-to-leaf path) to the tree.
    /// Add nodes that don't exist. Update actions or subscription IDs
    /// for terminal nodes at this stage.
    pub(crate) fn add_pattern(&mut self, pattern: &FlatPattern, 
                              pattern_id: usize, datatype: &DataType,
                              filter_id: usize,
                              subscription_str: &String) {
        
        // Skip patterns that already terminated
        if pattern.predicates.iter().all(|p| p.is_prev_layer(self.filter_layer, datatype)) {
            return;
        }

        let mut node = &mut self.root;
        node.patterns.push(pattern_id);
        for predicate in pattern.predicates.iter() {
            // Next predicate shouldn't be processed; 
            // node should be a non-terminal leaf node
            if predicate.is_next_layer(self.filter_layer) {
                let actions = datatype.with_nonterm_filter(self.filter_layer);
                node.actions.push(&actions);
                self.actions.push(&actions);
                // Stop descending - no terminal actions for this predicate
                return;
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
                true => { node.get_children_of(predicate) }
                false => { vec![] }
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
        if datatype.should_deliver(self.filter_layer, &node.pred) {
            node.deliver.insert(Deliver { id: filter_id, as_str: subscription_str.clone() });
        } else {
            let actions = datatype.with_term_filter(self.filter_layer);
            node.actions.push(&actions);
            self.actions.push(&actions);
        }
    }

    /// Returns a copy of the subtree rooted at Node `id`
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

    /// Best-effort to give the filter generator hints as to where an "else" 
    /// statement can go between two predicates.
    pub fn mark_mutual_exclusion(&mut self) {
        fn mark_mutual_exclusion(node: &mut PNode) {
            // TODO messy
            if !node.children.is_empty() {
                mark_mutual_exclusion(&mut node.children[0]);
            }
            if node.children.len() <= 1 { 
                return;
            }
            
            try_reorder(&mut node.children);

            for idx in 1..node.children.len() {
                mark_mutual_exclusion(&mut node.children[idx]);
                // Look for mutually exclusive predicates
                if node.children[idx].pred.is_excl(&node.children[idx - 1].pred) {
                    node.children[idx].if_else = true;
                }
                // If the result is equivalent (e.g., same CB in delivery filter) for child nodes, 
                // then we can safely use first match
                if node.children[idx].result_eq(&node.children[idx - 1]) {
                    node.children[idx].if_else = true;
                }
                // TODO more optimizations with branches here...
            }
        }
        mark_mutual_exclusion(&mut self.root);
    }

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

    /// Removes some patterns that are covered by others
    /// Should be called after tree is completely built
    pub fn prune_branches(&mut self) {

        fn prune(node: &mut PNode, on_path_actions: &Actions, on_path_deliver: &HashSet<String>) {
            // Remove redundant delivery
            let mut my_deliver = on_path_deliver.clone();
            let mut new_ids = HashSet::new();
            for i in &node.deliver {
                if !my_deliver.contains(&i.as_str) {
                    my_deliver.insert(i.as_str.clone());
                    new_ids.insert(i.clone());
                }
            }
            node.deliver = new_ids;
            // Remove redundant actions
            let mut my_actions = on_path_actions.clone();
            if !node.actions.drop() {
                node.actions.unique(&my_actions);
                my_actions.push(&node.actions);
            }
            // Prune children
            let mut new_children = vec![];
            for child in node.children.iter_mut() {
                prune(child, &my_actions, &my_deliver);
                // Backtrack: retain only those with actions, deliver, or children
                if !child.actions.drop() || !child.children.is_empty() || !child.deliver.is_empty() {
                    new_children.push(child.clone());
                }
            }
            node.children = new_children;
        }

        let on_path_actions = Actions::new();
        let on_path_deliver = HashSet::new();
        prune(&mut self.root, &on_path_actions, &on_path_deliver);
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


    /// modified from https://vallentin.dev/2019/05/14/pretty-print-tree
    fn pprint(&self) -> String {
        fn pprint(s: &mut String, node: &PNode, prefix: String, last: bool) {
            let prefix_current = if last { "`- " } else { "|- " };
            
            let s_next = format!(
                "{}{}{}: {}\n",
                prefix, prefix_current, node.id, node
            );
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

    // For writing intermediate output to file
    pub fn to_filter_string(&self) -> String {
        fn to_filter_string(p: &PNode, all: &mut Vec<String>, curr: String) {
            let mut curr = curr;
            if curr == "" { 
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
        let as_str: String = all_filters.join(" or ");
        as_str.into()
    }

    // For "packet"-layer filter
    pub fn get_packet_subtree(&self) -> PTree {
        fn get_packet_subtree(p: &mut PNode) {
            p.children.retain( |x| x.pred.on_packet() );
            for child in &mut p.children {
                get_packet_subtree(child);
            }
        }
        let mut output = (*self).clone();
        get_packet_subtree(&mut output.root);
        output
    }

    // For "connection"-layer filter
    pub fn get_connection_subtree(&self) -> PTree {
        fn get_connection_subtree(p: &mut PNode) {
            p.children.retain( |x| x.pred.on_packet() || x.pred.on_proto() );
            for child in &mut p.children {
                get_connection_subtree(child);
            }
        }
        let mut output = (*self).clone();
        get_connection_subtree(&mut output.root);
        output
    }
}

impl fmt::Display for PTree {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Tree {}\n,{}", &self.filter_layer, self.pprint())?;
        Ok(())
    }
}

impl PartialEq for PNode {

    fn eq(&self, other: &PNode) -> bool {
        // Same "level"
        if matches!(self.pred, Predicate::Unary { .. })  || 
           matches!(other.pred, Predicate::Unary { .. }) {
            return true;
        }
        // Considered "equal" if same protocol and same field
        if let Predicate::Binary { protocol: proto, field: field_name,
            op: _op, value: _val } = &self.pred {
            if let Predicate::Binary { protocol: peer_proto, field: peer_field_name,
                                    op: _peer_op, value: _peer_val } = &other.pred {
                return proto == peer_proto && field_name == peer_field_name;
            }
        }

        return false;
    }

}
impl Eq for PNode { }

impl PartialOrd for PNode {

    fn partial_cmp(&self, other: &PNode) -> Option<Ordering> {
        if self == other {
            return Some(Ordering::Equal);
        }
        Some(self.cmp(other))
    }

}

impl Ord for PNode {

    fn cmp(&self, other: &PNode) -> Ordering {
        if self == other {
            return Ordering::Equal;
        }

        if let Predicate::Binary { protocol: proto, field: field_name,
            op: _op, value: _val } = &self.pred {
            if let Predicate::Binary { protocol: peer_proto, field: peer_field_name,
                                    op: _peer_op, value: _peer_val } = &other.pred {
                if proto == peer_proto {
                    return field_name.name().cmp(peer_field_name.name());
                }
                return proto.name().cmp(peer_proto.name());
            }
        }

        return Ordering::Less;
    }
}

pub(super) fn try_reorder(input: &mut Vec<PNode>) {
    if input.len() < 3 { return; }
    input.sort();
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::filter::*;

    #[test]
    fn core_ptree_session() {        
        let datatype_str_conn = "cb_1(Connection)".to_string();
        let datatype_conn = DataType::new_default_connection();
        let datatype_str_session = "cb_2(Session)".to_string();
        let datatype_session = DataType::new_default_session();
        
        let filter = Filter::new("tls.sni = \'abc\'").unwrap();

        // Add Conn and Session-layer datatypes with Session-level filter
        let mut ptree = PTree::new_empty(FilterLayer::Session);
        ptree.add_filter(&filter.get_patterns_flat(), &datatype_conn, 0, 
        &datatype_str_conn);
        ptree.add_filter(&filter.get_patterns_flat(), &datatype_session, 1, 
                         &datatype_str_session);
        
        let mut expected_actions = Actions::new();
        expected_actions.data |= ActionData::ConnDataTrack | ActionData::SessionTrack;
        expected_actions.terminal_actions |= ActionData::ConnDataTrack | ActionData::SessionTrack;
        assert!(ptree.actions == expected_actions);
        assert!(!ptree.get_subtree(4).unwrap().deliver.is_empty());

        // Add filter that terminates at connection layer; should be no-op
        let noop_filter = Filter::new("tls").unwrap();
        ptree.add_filter(&noop_filter.get_patterns_flat(), &datatype_conn, 0, 
        &datatype_str_conn);
        assert!(ptree.get_subtree(3).unwrap().actions.drop());
        // println!("{}", ptree);

        // Session ptree with "or" should exclude patterns that terminate at upper layers
        let filter = Filter::from_str("(ipv4 and tls.sni = \'abc\') or (ipv4.dst_addr = 1.1.1.1/32)").unwrap();
        let mut ptree: PTree = PTree::new_empty(FilterLayer::Session);
        ptree.add_filter(&filter.get_patterns_flat(), &datatype_conn, 0, &datatype_str_conn);
        assert!(ptree.size == 5); // eth - ipv4 - tls - tls sni
    }

    #[test]
    fn core_ptree_proto() {
        let mut expected_actions = Actions::new();
        
        let filter_conn = Filter::from_str("ipv4 and tls").unwrap();
        let datatype_str = "cb_1(Connection)".to_string();
        let datatype: DataType = DataType::new_default_connection();
        
        // Connection-level datatype matching at connection level
        let mut ptree = PTree::new_empty(FilterLayer::Protocol);
        ptree.add_filter(&filter_conn.get_patterns_flat(), &datatype, 0, 
        &datatype_str);
        expected_actions.data |= ActionData::ConnDataTrack;
        expected_actions.terminal_actions |= ActionData::ConnDataTrack;
        // println!("{}", ptree);
        assert!(ptree.actions == expected_actions);
        
        // Session-level datatype matching at session level
        let filter = Filter::from_str("ipv4 and tls.sni = \'abc\'").unwrap();
        let datatype_str = "cb_2(Session)".to_string();
        let datatype = DataType::new_default_session();
        ptree.add_filter(&filter.get_patterns_flat(), &datatype, 0, &datatype_str);
        expected_actions.data |= ActionData::SessionFilter;
        assert!(ptree.actions == expected_actions);

        // Session-level datatype matching at connection level
        let filter = Filter::from_str("ipv4 and http").unwrap();
        ptree.add_filter(&filter.get_patterns_flat(), &datatype, 0, &datatype_str);
        expected_actions.data |= ActionData::SessionDeliver;
        expected_actions.terminal_actions |= ActionData::SessionDeliver;
        assert!(ptree.actions == expected_actions);
    }

    #[test]
    fn core_ptree_packet() { 
        let mut expected_actions = Actions::new();
        let filter = Filter::from_str("ipv4 and tls").unwrap();
        let datatype_str = "cb_1(Connection)".to_string();
        let datatype: DataType = DataType::new_default_connection();
        let mut ptree = PTree::new_empty(FilterLayer::Packet);
        ptree.add_filter(&filter.get_patterns_flat(), &datatype, 0, &datatype_str);

        expected_actions.data |= ActionData::ProtoFilter | ActionData::ConnDataTrack;
        // println!("{}", ptree);
        assert!(ptree.actions == expected_actions);

        // Packet ptree should exclude patterns that terminate at lower layers
        let filter = Filter::from_str("ipv4.dst_addr = 1.1.1.1 or (ipv4 and tls)").unwrap();
        let mut ptree = PTree::new_empty(FilterLayer::Packet);
        let datatype = DataType::new_default_packet();
        let datatype_str = "cb_1(ZcFrame)".to_string();
        ptree.add_filter(&filter.get_patterns_flat(), &datatype, 0, &datatype_str);
        ptree.prune_branches();
        ptree.mark_mutual_exclusion();
        assert!(ptree.size == 3); // eth - ipv4 - tcp; ipv4.dst_addr should be prev. layer (delivered)
        expected_actions.clear();
        expected_actions.data = ActionData::ProtoFilter | ActionData::PacketTrack;
        assert!(ptree.actions == expected_actions);

        let mut ptree = PTree::new_empty(FilterLayer::PacketContinue);
        ptree.add_filter(&filter.get_patterns_flat(), &datatype, 0, &datatype_str);
        assert!(ptree.size == 4);
    }

    #[test]
    fn core_ptree_pkt_deliver() {
        let filter = Filter::from_str("ipv4 and tls").unwrap();
        let datatype_str = "cb_1(Packet)".to_string();
        let datatype: DataType = DataType::new_default_packet();
        let mut ptree = PTree::new_empty(FilterLayer::PacketDeliver);
        ptree.add_filter(&filter.get_patterns_flat(), &datatype, 0, &datatype_str);
        assert!(!ptree.get_subtree(3).unwrap().deliver.is_empty());
        
        let mut ptree = PTree::new_empty(FilterLayer::Packet);
        ptree.add_filter(&filter.get_patterns_flat(), &datatype, 0, &datatype_str);
        let mut expected_actions = Actions::new();
        expected_actions.data |= ActionData::PacketTrack | ActionData::ProtoFilter;
        assert!(ptree.actions == expected_actions);
    }

    // \todo: asserts to check for correctness

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
        
        let datatype_str_conn = "cb_1(Connection)".to_string();
        let datatype_conn = DataType::new_default_connection();
        let datatype_str_session = "cb_1(Session)".to_string();
        let datatype_session = DataType::new_default_session();

        let mut ptree = PTree::new_empty(FilterLayer::Packet);

        let filter = Filter::from_str(filter).unwrap();
        ptree.add_filter(&filter.get_patterns_flat(), &datatype_session, 0, &datatype_str_session);
        let filter = Filter::from_str(filter_child1).unwrap();
        ptree.add_filter(&filter.get_patterns_flat(), &datatype_session, 1, &"1.2.0.0/16".to_string());
        let filter = Filter::from_str(filter_child2).unwrap();
        ptree.add_filter(&filter.get_patterns_flat(), &datatype_conn, 2, &datatype_str_conn);
        let filter: Filter = Filter::from_str(filter_child3).unwrap();
        ptree.add_filter(&filter.get_patterns_flat(), &datatype_conn, 3, &datatype_str_conn);
        let filter = Filter::from_str(filter_child4).unwrap();
        ptree.add_filter(&filter.get_patterns_flat(), &datatype_conn, 4, &datatype_str_conn);
        let filter = Filter::from_str(filter_child5).unwrap();
        ptree.add_filter(&filter.get_patterns_flat(), &datatype_conn, 5, &datatype_str_conn);

        // no_op
        ptree.add_filter(&filter.get_patterns_flat(), &datatype_conn, 4, &datatype_str_conn);

        // println!("{}", ptree);
        assert!(ptree.size == 13);
        ptree.prune_branches();
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
        let datatype_str_conn = "cb_1(Connection)".to_string();
        let datatype_conn = DataType::new_default_connection();
        
        let mut ptree = PTree::new_empty(FilterLayer::ConnectionDeliver);

        let filter = Filter::from_str(filter).unwrap();
        ptree.add_filter(&filter.get_patterns_flat(), &datatype_conn, 0, &datatype_str_conn);
        let filter = Filter::from_str(filter_child).unwrap();
        ptree.add_filter(&filter.get_patterns_flat(), &datatype_conn, 1, &datatype_str_conn);
        
        ptree.prune_branches();
        assert!(!ptree.to_filter_string().contains("1.3.3.1/31") && ptree.size == 3); // eth, ipv4, ipvr.src
    }
}