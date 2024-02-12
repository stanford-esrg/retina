use super::ast::*;
use super::pattern::{FlatPattern, LayeredPattern};
use super::Filter;
use super::actions::*;

use std::fmt;
use std::collections::HashSet;
use std::cmp::{Ordering, PartialOrd};

/// Indicates whether the filter will deliver a subscription 
/// or return an action.
#[derive(Debug, Clone, Copy)]
pub enum FilterType {
    /// Leaf nodes (per sub-filter) are 
    /// expected to contain action(s) to be applied
    Action(FilterLayer),
    /// Leaf nodes (per sub-filter) are 
    /// expected to contain subscription id(s) for delivery
    Deliver(FilterLayer)
}

impl fmt::Display for FilterType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FilterType::Action(layer) => write!(f, "Action: {}", layer),
            FilterType::Deliver(layer) => write!(f, "Deliver: {}", layer),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum FilterLayer {
    /// Action filters ///
    
    /// Filter applied to map a packet to actions
    Packet, 
    /// Filter applied to map connection data to actions
    Connection, 
    /// Filter applied to map session data to actions
    Session,

    /// Delivery filters  ///
    /// Will deliver reference to data to correct subscription. ///

    /// Filter applied when a packet is ready to be delivered
    PacketDeliver,
    /// Filter applied when connection data is ready to be
    /// delivered (`on terminate` for matched connection)
    ConnectionDeliver,
    /// Filter applied when parsed session data is ready to be
    /// delivered (`deliver session` on match).
    SessionDeliver, 

    /// Unknown
    None
}

impl fmt::Display for FilterLayer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FilterLayer::Packet => write!(f, "P"),
            FilterLayer::Connection => write!(f, "C"),
            FilterLayer::Session => write!(f, "S"),
            FilterLayer::PacketDeliver => write!(f, "P (deliver_frame)"),
            FilterLayer::ConnectionDeliver => write!(f, "C (on_terminate)"),
            FilterLayer::SessionDeliver => write!(f, "S (session_on_match)"),
            FilterLayer::None => write!(f, "Unknown"),
        }
    }
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
    pub deliver: HashSet<usize>,

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

    /// Utility - returns node with matching `pred`
    /// Should be checked to avoid adding redundant nodes in case
    /// filters are added in non-descending order (TODOTR can be avoided) 
    fn has_descendent(&self, pred: &Predicate) -> bool {
        for n in &self.children {
            if &n.pred == pred { 
                return true;
            }
            if n.pred.is_child(pred) {
                if n.has_descendent(pred) {
                    return true;
                }
            }
        }
        false
    }

    fn get_descendent(&mut self, pred: &Predicate) -> Option<&mut PNode> {
        for n in &mut self.children {
            if &n.pred == pred { 
                return Some(n);
            }
            if n.pred.is_child(pred) {
                if let Some(c) = n.get_descendent(pred) {
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
            write!(f, " -- A: {}", self.actions.to_string())?;
        }
        if !self.deliver.is_empty() {
            write!(f, " D: ")?;
            for i in &self.deliver {
                write!(f, "{} ", i)?;
            }
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
#[derive(Debug)]
pub struct PTree {
    /// Root node
    pub root: PNode,

    /// Number of nodes in tree
    pub size: usize,

    /// Possible actions
    pub actions: Actions,

    /// Which filter this PTree represents
    pub filter_type: FilterType,
}

impl PTree {

    pub fn new_empty(filter_type: FilterType) -> Self {
        let pred = Predicate::Unary { protocol: protocol!("ethernet"), };
        let root = PNode::new(pred, 0); 
        let ptree = PTree { 
            root, 
            size: 1, 
            actions: Actions::new(),
            filter_type 
        };
        ptree
    }

    pub fn new_from_str(filter_raw: &str, 
                        filter_type: FilterType, 
                        actions: &Actions, 
                        filter_id: usize) -> Option<Self> {

        if let Ok(filter) = Filter::from_str(filter_raw) {
            return Some(PTree::new(&filter.get_patterns_flat(), 
                        filter_type, actions, filter_id));
        }
        None
    }

    /// Creates a new predicate tree from a slice of FlatPatterns
    pub fn new(patterns: &[FlatPattern], 
               filter_type: FilterType,
               actions: &Actions,
               filter_id: usize) -> Self {
        let pred = Predicate::Unary { protocol: protocol!("ethernet"), };
        let root = PNode::new(pred, 0); 
        let mut ptree = PTree { 
            root, 
            size: 1, 
            actions: actions.clone(), // Starting value for possible actions
            filter_type 
        };
        ptree.build_tree(patterns, actions, filter_id);
        ptree
    }

    /// Add a filter to an existing PTree
    /// Applied for multiple subscriptions, when multiple actions 
    /// and/or delivery filters will be checked at the same stage
    pub fn add_filter(&mut self, patterns: &[FlatPattern], 
                      actions: &Actions, filter_id: usize) {
        self.build_tree(patterns, actions, filter_id);
        if matches!(self.filter_type, FilterType::Action(_)) {
            self.actions.update(&actions); // Possible actions
        }
    }

    pub fn add_filter_from_str(&mut self, filter_raw: &str, 
                                actions: &Actions, filter_id: usize) {
        if let Ok(filter) = Filter::from_str(filter_raw) {
            self.add_filter(&filter.get_patterns_flat(), 
                            actions, filter_id);
        }
    }

    /// Add all given patterns (root-to-leaf paths) to a PTree
    pub fn build_tree(&mut self, patterns: &[FlatPattern], 
                      actions: &Actions, filter_id: usize) {
        // add each pattern to tree
        let mut added = false;
        for (i, pattern) in patterns.iter().enumerate() {
            added = added || !pattern.predicates.is_empty();
            self.add_pattern(pattern, i, actions, filter_id);
        }

        // Need to terminate somewhere
        if !added {
            if matches!(self.filter_type, FilterType::Action(_)) {
                self.root.actions.update(actions);
            } else {
                self.root.deliver.insert(filter_id);
            }
        }
    }

    /// Add a single pattern (root-to-leaf path) to the tree.
    /// Add nodes that don't exist. Update actions or subscription IDs
    /// for terminal nodes at this stage.
    pub(crate) fn add_pattern(&mut self, pattern: &FlatPattern, 
                              pattern_id: usize, actions: &Actions,
                              filter_id: usize) {
        let mut node = &mut self.root;
        node.patterns.push(pattern_id);
        for predicate in pattern.predicates.iter() {
            // TODOTR this is messy, also need to figure out delivery filter collapse
            if matches!(self.filter_type, FilterType::Action(_)) {
                if node.has_descendent(predicate) {
                    node = node.get_descendent(predicate).unwrap();
                    node.patterns.push(pattern_id);
                    continue;
                }
                if node.has_parent(predicate) {
                    node = node.get_parent(predicate, self.size).unwrap();
                }
                let children = match node.has_children_of(predicate) {
                    true => { node.get_children_of(predicate) }
                    false => { vec![] }
                };
                node.children.extend(children);
            }
            if !node.has_child(predicate) {
                node.children.push(PNode::new(predicate.clone(), self.size));
                self.size += 1;
            }
            node = node.get_child(predicate);
            node.patterns.push(pattern_id);
        }

        if matches!(self.filter_type, FilterType::Action(_)) {
            node.actions.update(actions);
        } else {
            node.deliver.insert(filter_id);
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
                if node.children[idx].pred.is_excl(&node.children[idx - 1].pred) {
                    node.children[idx].if_else = true;
                }
            }
        }
        mark_mutual_exclusion(&mut self.root);
    }

    fn update_size(&mut self) {

        fn count_nodes(node: &PNode) -> usize {
            let mut count = 1;
            for child in &node.children {
                count += count_nodes(child);
            }
            count
        }
        self.size = count_nodes(&self.root);
        
    }

    /// Removes some patterns that are covered by others
    /// This does NOT check for matching actions and should ONLY 
    /// be used on a PTree that represents a single action or single 
    /// subscription (delivery)!!!!
    pub fn prune_branches(&mut self) {
        fn prune(node: &mut PNode, filter_type: &FilterType) {
            // No actions and no delivery
            if matches!(filter_type, FilterType::Action(_)) && !node.actions.drop() {
                node.children.clear();
            } else if matches!(filter_type, FilterType::Deliver(_)) && !node.deliver.is_empty() {
                node.children.clear();
            }
            for child in node.children.iter_mut() {
                prune(child, filter_type);
            }
        }
        prune(&mut self.root, &self.filter_type);
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
}

impl fmt::Display for PTree {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Tree {}\n,{}", &self.filter_type, self.pprint())?;
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

    /* 
    if input.len() <= 3 { return; }
    let ipv4 = input.iter().filter( |n| {
        if let Predicate::Binary { protocol: proto, field: _field_name,
            op: _op, value: val } = n.pred {
                return proto == protocol!("ipv4");
            }
            return false;
    } ).count();
    let ipv6 = input.iter().filter( |n| {
        if let Predicate::Binary { protocol: proto, field: _field_name,
            op: _op, value: _val } = &n.pred {
                return proto == &protocol!("ipv6");
            }
            return false;
    } ).count();

    if ipv4 < 3 && ipv6 < 3 { return; }

     */

}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn core_ptree_build() {
        let filter = "ipv4 and tls";
        let mut actions = Actions::new();
        actions.data.set(ActionFlags::ConnDataTrack);
        actions.terminal_actions.set(ActionFlags::ConnDataTrack);
        let mut ptree = PTree::new_from_str(filter,
                                    FilterType::Action(FilterLayer::Connection), &actions, 0).unwrap();
        actions.clear();
        actions.data.set(ActionFlags::ConnParse);
        ptree.add_filter_from_str("ipv4.src_addr = 1.2.3.0/24", &actions, 1);
        // println!("{}", ptree);
        
        let mut ptree = PTree::new_from_str("ipv4 and tls",
            FilterType::Deliver(FilterLayer::SessionDeliver), &Actions::new(), 0).unwrap();
        ptree.add_filter_from_str("ipv4.src_addr = 1.2.3.0/24 and http", &Actions::new(), 1);
        // println!("{}", ptree);
    }

    // \todo: asserts to check for correctness

    #[test]
    fn core_ptree_with_children() {
        let filter = "ipv4 and tls";
        let filter_child1 = "ipv4.addr = 1.2.0.0/16";
        let filter_child2 = "ipv4.addr = 1.2.2.0/24";
        let filter_child3 = "ipv4.addr = 1.2.3.0/24";
        let filter_child4 = "ipv4.src_addr = 1.2.3.1/31";
        let filter_child5 = "ipv4.src_addr = 1.2.3.1/32";
        let mut actions = Actions::new();
        actions.data.set(ActionFlags::ConnDataTrack);
        actions.terminal_actions.set(ActionFlags::ConnDataTrack);
        
        let mut ptree = PTree::new_from_str(filter,
                                    FilterType::Action(FilterLayer::Connection), &actions, 0).unwrap();
        actions.clear();
        actions.data.set(ActionFlags::ConnParse);

        ptree.add_filter_from_str(filter_child1, &actions, 0);
        ptree.add_filter_from_str(filter_child2, &actions, 0);
        ptree.add_filter_from_str(filter_child3, &actions, 0);
        ptree.add_filter_from_str(filter_child4, &actions, 0);
        ptree.add_filter_from_str(filter_child5, &actions, 0);
        ptree.add_filter_from_str(filter_child4, &actions, 0); // no_op
        ptree.add_filter_from_str(filter_child5, &actions, 0); // no_op
        
        assert!(ptree.size == 12);

        // Should be `ipv4.src_addr = 1.2.3.0/24`
        let node = ptree.get_subtree(9).unwrap();
        assert!(node.children.len() == 1); // `ipv4.src_addr = 1.2.3.1/31`
        assert!(node.children.get(0)
                             .unwrap()
                             .children
                             .len() == 1); // `ipv4.src_addr = 1.2.3.1/32`

        //println!("{}", ptree); // check output
        let filter_parent = "ipv4.addr = 1.0.0.0/8";
        let filter_child = "ipv4.addr = 1.5.0.0/16";
        ptree.add_filter_from_str(filter_child, &actions, 0);
        ptree.add_filter_from_str(filter_parent, &actions, 0);
        println!("{}", ptree);
        assert!(ptree.size == 16);
        let node = ptree.get_subtree(15).unwrap(); // ipv4.src_addr = 1.0.0.0/8
        assert!(node.children.len() == 2);
    }

    #[test]
    fn core_ptree_prune() {
        let filter = "ipv4";
        let filter_child1 = "ipv4.addr = 1.2.0.0/16";
        let filter_child2 = "ipv4.addr = 1.2.2.0/24";

        let mut actions = Actions::new();
        actions.data.set(ActionFlags::ConnDataTrack);
        actions.terminal_actions.set(ActionFlags::ConnDataTrack);

        let mut ptree = PTree::new_from_str(filter,
            FilterType::Action(FilterLayer::Packet), &actions, 0).unwrap();
        
        ptree.add_filter_from_str(filter_child1, &actions, 0);
        assert!(ptree.size == 4);
        ptree.prune_branches();
        assert!(ptree.size == 2);
        
        let mut ptree = PTree::new_from_str(filter_child1, 
                    FilterType::Action(FilterLayer::Packet), &actions, 0).unwrap();
        ptree.add_filter_from_str(filter_child2, &actions, 0);
        assert!(ptree.size == 6);
        ptree.prune_branches();
        assert!(ptree.size == 4);
    }
}