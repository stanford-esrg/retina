use super::ast::*;
use super::pattern::{FlatPattern, LayeredPattern};

use std::fmt;

/// Represents the sub-filter that a predicate node terminates.
#[derive(Debug, Clone)]
pub enum Terminate {
    Packet,
    Connection,
    Session,
    None,
}

impl fmt::Display for Terminate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Terminate::Packet => write!(f, "p"),
            Terminate::Connection => write!(f, "c"),
            Terminate::Session => write!(f, "s"),
            Terminate::None => write!(f, ""),
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

    /// Whether the node terminates a pattern
    pub is_terminal: bool,

    /// Sub-filter terminal (packet, connection, or session)
    pub terminates: Terminate,

    /// The patterns for which the predicate is a part of
    pub patterns: Vec<usize>,

    /// Child PNodes
    pub children: Vec<PNode>,
}

impl PNode {
    fn new(pred: Predicate, id: usize) -> Self {
        PNode {
            id,
            pred,
            is_terminal: false,
            terminates: Terminate::None,
            patterns: vec![],
            children: vec![],
        }
    }

    fn has_child(&self, pred: &Predicate) -> bool {
        self.children.iter().any(|n| &n.pred == pred)
    }

    fn get_child(&mut self, pred: &Predicate) -> &mut PNode {
        self.children.iter_mut().find(|n| &n.pred == pred).unwrap()
    }
}

impl fmt::Display for PNode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.pred)?;
        Ok(())
    }
}

/// A n-ary tree representing a Filter.
/// Paths from root to leaf represent a pattern for a frame to match.
#[derive(Debug)]
pub struct PTree {
    /// Root node
    pub root: PNode,

    /// Number of nodes in tree
    pub size: usize,
}

impl PTree {
    /// Creates a new predicate tree from a slice of FlatPatterns
    pub fn new(patterns: &[FlatPattern]) -> Self {
        let root = PNode {
            id: 0,
            pred: Predicate::Unary {
                protocol: protocol!("ethernet"),
            },
            is_terminal: false,
            terminates: Terminate::None,
            patterns: vec![],
            children: vec![],
        };
        let mut ptree = PTree { root, size: 1 };
        ptree.build_tree(patterns);
        ptree
    }

    // Converts PTree to vector of FlatPatterns (all root->leaf paths).
    // Useful for using the PTree to prune redundant branches then
    // converting back to FlatPatterns
    pub(crate) fn to_flat_patterns(&self) -> Vec<FlatPattern> {
        fn build_pattern(
            patterns: &mut Vec<FlatPattern>,
            predicates: &mut Vec<Predicate>,
            node: &PNode,
        ) {
            if *node.pred.get_protocol() != protocol!("ethernet") {
                predicates.push(node.pred.to_owned());
            }
            if node.is_terminal {
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

    // Converts PTree to vector of LayeredPatterns (all root->leaf paths).
    // Useful for using the PTree to prune redundant branches then
    // converting back to LayeredPatterns
    pub(crate) fn to_layered_patterns(&self) -> Vec<LayeredPattern> {
        let flat_patterns = self.to_flat_patterns();
        let mut layered = vec![];
        for pattern in flat_patterns.iter() {
            layered.extend(pattern.to_fully_qualified().expect("fully qualified"));
        }
        layered
    }

    pub(crate) fn build_tree(&mut self, patterns: &[FlatPattern]) {
        // add each pattern to tree
        for (i, pattern) in patterns.iter().enumerate() {
            self.add_pattern(pattern, i);
        }

        // TODO: maybe remove this to distinguish terminating a user-specified pattern
        if self.root.children.is_empty() {
            self.root.is_terminal = true;
            self.root.terminates = Terminate::Packet;
        }
    }

    pub(crate) fn add_pattern(&mut self, pattern: &FlatPattern, pattern_id: usize) {
        let mut node = &mut self.root;
        node.patterns.push(pattern_id);
        for predicate in pattern.predicates.iter() {
            if !node.has_child(predicate) {
                node.children.push(PNode::new(predicate.clone(), self.size));
                self.size += 1;

                if node.pred.on_packet() && predicate.on_connection() {
                    node.terminates = Terminate::Packet;
                } else if node.pred.on_connection() && predicate.on_session() {
                    node.terminates = Terminate::Connection;
                }
            }
            node = node.get_child(predicate);
            node.patterns.push(pattern_id);
        }

        node.is_terminal = true;
        if node.pred.on_packet() {
            node.terminates = Terminate::Packet;
        } else if node.pred.on_connection() {
            node.terminates = Terminate::Connection;
        } else if node.pred.on_session() {
            node.terminates = Terminate::Session;
        } else {
            log::error!("Terminal node but does not terminate a sub-filter")
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

    /// Returns list of subtrees rooted at packet terminal nodes.
    /// Used to generate connection filter.
    pub fn get_connection_subtrees(&self) -> Vec<PNode> {
        fn get_connection_subtrees(node: &PNode, list: &mut Vec<PNode>) {
            if matches!(node.terminates, Terminate::Packet) {
                list.push(node.clone());
            }
            for child in node.children.iter() {
                get_connection_subtrees(child, list);
            }
        }
        let mut list = vec![];
        get_connection_subtrees(&self.root, &mut list);
        list
    }

    /// Returns list of subtrees rooted at connection terminal nodes.
    /// Used to generate session filter.
    pub fn get_session_subtrees(&self) -> Vec<PNode> {
        fn get_session_subtrees(node: &PNode, list: &mut Vec<PNode>) {
            if matches!(node.terminates, Terminate::Connection) {
                list.push(node.clone());
            }
            for child in node.children.iter() {
                get_session_subtrees(child, list);
            }
        }
        let mut list = vec![];
        get_session_subtrees(&self.root, &mut list);
        list
    }

    /// Removes some patterns that are covered by others, but not all.
    /// (e.g. "ipv4 or ipv4.src_addr = 1.2.3.4" will remove "ipv4.src_addr = 1.2.3.4")
    pub fn prune_branches(&mut self) {
        fn prune(node: &mut PNode) {
            if node.is_terminal {
                node.children.clear();
            }
            for child in node.children.iter_mut() {
                prune(child);
            }
        }
        prune(&mut self.root);
    }

    /// modified from https://vallentin.dev/2019/05/14/pretty-print-tree
    fn pprint(&self) -> String {
        fn pprint(s: &mut String, node: &PNode, prefix: String, last: bool) {
            let prefix_current = if last { "`- " } else { "|- " };

            if node.is_terminal {
                s.push_str(
                    format!(
                        "{}{}{} ({}) {}*\n",
                        prefix, prefix_current, node, node.id, node.terminates
                    )
                    .as_str(),
                );
            } else {
                s.push_str(
                    format!(
                        "{}{}{} ({}) {}\n",
                        prefix, prefix_current, node, node.id, node.terminates
                    )
                    .as_str(),
                );
            }

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
        write!(f, "{}", self.pprint())?;
        Ok(())
    }
}
