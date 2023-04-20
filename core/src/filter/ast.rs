use super::hardware;

use std::collections::HashSet;
use std::fmt;

use bimap::BiMap;
use ipnet::{Ipv4Net, Ipv6Net};
use petgraph::algo;
use petgraph::graph::Graph;
use petgraph::graph::NodeIndex;

use crate::port::Port;

// TODO: define these relationships in protocols module
lazy_static! {
    pub(crate) static ref LAYERS: Graph::<ProtocolName, ()> = {
        let mut g = Graph::<ProtocolName, ()>::new();
        let ethernet = g.add_node(protocol!("ethernet"));
        let ipv4     = g.add_node(protocol!("ipv4"));
        let ipv6     = g.add_node(protocol!("ipv6"));
        let tcp      = g.add_node(protocol!("tcp"));
        let udp      = g.add_node(protocol!("udp"));
        let tls      = g.add_node(protocol!("tls"));
        let http     = g.add_node(protocol!("http"));
        let ssh      = g.add_node(protocol!("ssh"));
        let dns      = g.add_node(protocol!("dns"));
        // define valid outer layers for each protocol header
        g.extend_with_edges([
            (ipv4, ethernet),
            (ipv6, ethernet),
            (tcp, ipv4), (tcp, ipv6),
            (udp, ipv4), (udp, ipv6),
            (tls, tcp),
            (http, tcp),
            (ssh, tcp),
            (dns, udp), (dns, tcp),
        ]);
        g
    };
}

lazy_static! {
    pub(crate) static ref NODE_BIMAP: BiMap::<NodeIndex, ProtocolName> = {
        LAYERS
            .node_indices()
            .map(|i| (i, LAYERS[i].clone()))
            .collect()
    };
}

/// Returns `true` if there is a path from `from` to `to` in the
/// protocol LAYERS graph.
fn has_path(from: &ProtocolName, to: &ProtocolName) -> bool {
    // Returns `false` if from == to
    let from_node = NODE_BIMAP.get_by_right(from);
    let to_node = NODE_BIMAP.get_by_right(to);

    match (from_node, to_node) {
        (Some(from_node), Some(to_node)) => {
            let paths: HashSet<Vec<NodeIndex>> =
                algo::all_simple_paths(&*LAYERS, *from_node, *to_node, 0, None)
                    .collect::<HashSet<_>>();
            !paths.is_empty()
        }
        _ => false,
    }
}

/// An individual filter predicate
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Predicate {
    Unary {
        protocol: ProtocolName,
    },
    Binary {
        protocol: ProtocolName,
        field: FieldName,
        op: BinOp,
        value: Value,
    },
}

impl Predicate {
    /// Returns the name of the protocol.
    pub fn get_protocol(&self) -> &ProtocolName {
        match self {
            Predicate::Unary { protocol } => protocol,
            Predicate::Binary { protocol, .. } => protocol,
        }
    }

    /// Returns `true` if predicate is a unary constraint.
    pub fn is_unary(&self) -> bool {
        matches!(self, Predicate::Unary { .. })
    }

    /// Returns `true` if predicate is a binary constraint.
    pub fn is_binary(&self) -> bool {
        matches!(self, Predicate::Binary { .. })
    }

    /// Returns `true` if predicate can be pushed to a packet filter.
    /// i.e., the lowest filter level needed to apply the predicate is a packet filter.
    pub fn on_packet(&self) -> bool {
        !self.needs_conntrack()
    }

    /// Returns `true` if predicate can be satisfied by a connection filter.
    /// i.e., the lowest filter level needed to apply the predicate is a connection filter.
    pub fn on_connection(&self) -> bool {
        self.needs_conntrack() && self.is_unary()
    }

    /// Returns `true` if predicate can be satisfied by a session filter.
    /// i.e., the lowest filter level needed to apply the predicate is a session filter.
    pub fn on_session(&self) -> bool {
        self.needs_conntrack() && self.is_binary()
    }

    /// Returns `true` if the predicate's protocol requires connection tracking
    /// i.e., is an application-layer protocol that runs on top of TCP or UDP.
    fn needs_conntrack(&self) -> bool {
        has_path(self.get_protocol(), &protocol!("tcp"))
            || has_path(self.get_protocol(), &protocol!("udp"))
    }

    /// Returns `true` if predicate can be pushed down to hardware port.
    pub(super) fn is_hardware_filterable(&self, port: &Port) -> bool {
        hardware::device_supported(self, port)
    }
}

impl fmt::Display for Predicate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        match &self {
            Predicate::Unary { protocol } => write!(f, "{}", protocol),
            Predicate::Binary {
                protocol,
                field,
                op,
                value,
            } => write!(f, "{}.{} {} {}", protocol, field, op, value),
        }
    }
}

/// Name of the protocol used in filter syntax
/// By convention, this should be the all-lowercase version of the protocol struct identifier
#[derive(Default, Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProtocolName(pub String);

impl ProtocolName {
    pub fn name(&self) -> &str {
        self.0.as_str()
    }
}

impl fmt::Display for ProtocolName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f, "{}", self.0)
    }
}

/// Name of the field used in filter syntax
/// By convention, this should be all-lowercase
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FieldName(pub String);

impl FieldName {
    pub fn name(&self) -> &str {
        self.0.as_str()
    }

    // combined expressions are those like ipv4.addr, tcp.port, etc. which
    // expand to dst OR src
    pub fn is_combined(&self) -> bool {
        self.name() == "addr" || self.name() == "port"
    }
}

impl fmt::Display for FieldName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f, "{}", self.0)
    }
}

/// Allowed binary operators in a binary predicate
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum BinOp {
    Eq,
    Ne,
    Ge,
    Le,
    Gt,
    Lt,
    In,
    Re,
    En,
}

impl fmt::Display for BinOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        match self {
            BinOp::Eq => write!(f, "="),
            BinOp::Ne => write!(f, "!="),
            BinOp::Ge => write!(f, ">="),
            BinOp::Le => write!(f, "<="),
            BinOp::Gt => write!(f, ">"),
            BinOp::Lt => write!(f, "<"),
            BinOp::In => write!(f, "in"),
            BinOp::Re => write!(f, "matches"),
            BinOp::En => write!(f, "eq"),
        }
    }
}

/// Allowed RHS values in a binary predicate
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Value {
    Int(u64),
    IntRange { from: u64, to: u64 },
    Ipv4(Ipv4Net),
    Ipv6(Ipv6Net),
    Text(String),
}

impl fmt::Display for Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        match self {
            Value::Int(val) => write!(f, "{}", val),
            Value::IntRange { from, to } => write!(f, "{}..{}", from, to),
            Value::Ipv4(net) => write!(f, "{}", net),
            Value::Ipv6(net) => write!(f, "{}", net),
            Value::Text(val) => write!(f, "{}", val),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn core_ast_has_path() {
        assert!(has_path(&protocol!("tcp"), &protocol!("ethernet")));
        assert!(has_path(&protocol!("dns"), &protocol!("ipv6")));
        assert!(has_path(&protocol!("dns"), &protocol!("udp")));
        assert!(has_path(&protocol!("tcp"), &protocol!("ipv4")));
        assert!(!has_path(&protocol!("ipv4"), &protocol!("tcp")));
        assert!(!has_path(&protocol!("ipv4"), &protocol!("ipv4")));
        assert!(!has_path(&protocol!("http"), &protocol!("udp")));
        assert!(!has_path(&protocol!("tls"), &protocol!("ssh")));
    }

    #[test]
    fn core_ast_packet_predicates() {
        let ipv4_unary = Predicate::Unary {
            protocol: protocol!("ipv4"),
        };
        assert!(ipv4_unary.on_packet());

        let udp_binary = Predicate::Binary {
            protocol: protocol!("udp"),
            field: field!("dst_port"),
            op: BinOp::Eq,
            value: Value::Int(53),
        };
        assert!(udp_binary.on_packet());

        let tcp_unary = Predicate::Unary {
            protocol: protocol!("tcp"),
        };
        assert!(tcp_unary.on_packet());

        let tcp_binary = Predicate::Binary {
            protocol: protocol!("tcp"),
            field: field!("port"),
            op: BinOp::Eq,
            value: Value::Int(80),
        };
        assert!(tcp_binary.on_packet());
    }

    #[test]
    fn core_ast_connection_predicates() {
        let tls_unary = Predicate::Unary {
            protocol: protocol!("tls"),
        };
        assert!(tls_unary.on_connection());

        let dns_unary = Predicate::Unary {
            protocol: protocol!("dns"),
        };
        assert!(dns_unary.on_connection());
    }

    #[test]
    fn core_ast_session_predicates() {
        let http_binary = Predicate::Binary {
            protocol: protocol!("http"),
            field: field!("method"),
            op: BinOp::Eq,
            value: Value::Text("GET".to_owned()),
        };
        assert!(http_binary.on_session());
    }
}
