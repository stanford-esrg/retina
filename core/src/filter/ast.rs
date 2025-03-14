use super::hardware;
use super::ptree::FilterLayer;
use super::Level;

use std::collections::HashSet;
use std::fmt;

use crate::protocols::stream::ConnData;
use bimap::BiMap;
use ipnet::{Ipv4Net, Ipv6Net};
use itertools::Itertools;
use petgraph::algo;
use petgraph::graph::Graph;
use petgraph::graph::NodeIndex;
use regex::Regex;

use crate::port::Port;

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
        let dns      = g.add_node(protocol!("dns"));
        let quic     = g.add_node(protocol!("quic"));
        let ssh      = g.add_node(protocol!("ssh"));
        // define valid outer layers for each protocol header
        g.extend_with_edges([
            (ipv4, ethernet),
            (ipv6, ethernet),
            (tcp, ipv4), (tcp, ipv6),
            (udp, ipv4), (udp, ipv6),
            (tls, tcp),
            (http, tcp),
            (dns, udp), (dns, tcp),
            (quic, udp), //TODO: tls over quic
            (ssh, tcp),
        ]);
        g
    };
}

lazy_static! {
    /// Graph of possible protocol layers used to build the filter tree.
    /// For example, "tls" must be preceded by "tcp".
    pub(crate) static ref NODE_BIMAP: BiMap::<NodeIndex, ProtocolName> = {
        LAYERS
            .node_indices()
            .map(|i| (i, LAYERS[i].clone()))
            .collect()
    };
}

// Returns `true` if there is a path from `from` to `to` in the
// protocol LAYERS graph.
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
    /// Matches on a protocol
    Unary { protocol: ProtocolName },
    /// Matches on a field in a protocol
    Binary {
        protocol: ProtocolName,
        field: FieldName,
        op: BinOp,
        value: Value,
    },
}

impl Predicate {
    // Returns the name of the protocol.
    pub fn get_protocol(&self) -> &ProtocolName {
        match self {
            Predicate::Unary { protocol } => protocol,
            Predicate::Binary { protocol, .. } => protocol,
        }
    }

    // Returns `true` if predicate is a unary constraint.
    pub fn is_unary(&self) -> bool {
        matches!(self, Predicate::Unary { .. })
    }

    // Returns `true` if predicate is a binary constraint.
    pub fn is_binary(&self) -> bool {
        matches!(self, Predicate::Binary { .. })
    }

    // Returns `true` if predicate can be pushed to a packet filter.
    // i.e., the lowest filter level needed to apply the predicate is a packet filter.
    pub fn on_packet(&self) -> bool {
        !self.needs_conntrack()
    }

    // Returns `true` if predicate *requires* raw packets
    // (i.e., cannot be connection-level data)
    pub fn req_packet(&self) -> bool {
        if !self.on_packet() {
            return false;
        }
        if let Predicate::Binary {
            protocol: _proto,
            field: field_name,
            ..
        } = self
        {
            return field_name.name() != "port"
                && field_name.name() != "addr"
                && !ConnData::supported_fields().contains(&field_name.name());
        }
        !ConnData::supported_protocols().contains(&self.get_protocol().name())
    }

    // Returns `true` if predicate can be satisfied by a connection filter.
    // i.e., the lowest filter level needed to apply the predicate is a connection filter.
    pub fn on_proto(&self) -> bool {
        self.needs_conntrack() && self.is_unary()
    }

    // Returns `true` if predicate can be satisfied by a session filter.
    // i.e., the lowest filter level needed to apply the predicate is a session filter.
    pub fn on_session(&self) -> bool {
        self.needs_conntrack() && self.is_binary()
    }

    // Returns `true` if the predicate's protocol requires connection tracking
    // i.e., is an application-layer protocol that runs on top of TCP or UDP.
    fn needs_conntrack(&self) -> bool {
        has_path(self.get_protocol(), &protocol!("tcp"))
            || has_path(self.get_protocol(), &protocol!("udp"))
    }

    pub(crate) fn is_next_layer(&self, filter_layer: FilterLayer) -> bool {
        match filter_layer {
            FilterLayer::Packet | FilterLayer::PacketContinue => !self.on_packet(),
            FilterLayer::Protocol => self.on_session(),
            FilterLayer::Session | FilterLayer::ConnectionDeliver | FilterLayer::PacketDeliver => {
                false
            }
        }
    }

    // Returns `true` if the predicate would have been checked at the previous
    // filter layer based on both the filter layer and the subscription level.
    pub(super) fn is_prev_layer(
        &self,
        filter_layer: FilterLayer,
        subscription_level: &Level,
    ) -> bool {
        match filter_layer {
            FilterLayer::PacketContinue => false,
            FilterLayer::Packet => {
                // Packet would have already been delivered in PacketContinue
                self.on_packet() && matches!(subscription_level, Level::Packet)
            }
            FilterLayer::PacketDeliver => {
                // Subscription not delivered in this filter
                !matches!(subscription_level, Level::Packet) ||
                    // Subscription delivered in PacketContinue
                    self.on_packet()
            }
            FilterLayer::Protocol => self.on_packet(),
            FilterLayer::Session => {
                (self.on_packet() || self.on_proto()) &&  // prev filter
                !matches!(subscription_level, Level::Session) // no delivery req'd
            }
            FilterLayer::ConnectionDeliver => {
                // Delivered elsewhere
                !matches!(subscription_level, Level::Connection | Level::Static) ||
                    // Delivered in packet filter
                    (matches!(subscription_level, Level::Static) && self.on_packet())
            }
        }
    }

    // Returns true if the predicate would have been checked at prev. layer
    // Does not consider subscription type; meant to be used for filter collapse.
    pub(super) fn is_prev_layer_pred(&self, filter_layer: FilterLayer) -> bool {
        match filter_layer {
            FilterLayer::PacketContinue => false,
            FilterLayer::Packet | FilterLayer::Protocol => self.on_packet(),
            FilterLayer::PacketDeliver | FilterLayer::ConnectionDeliver => true,
            FilterLayer::Session => self.on_packet() || self.on_proto(),
        }
    }

    pub(super) fn default_pred() -> Predicate {
        Predicate::Unary {
            protocol: protocol!("ethernet"),
        }
    }

    // Returns `true` if predicate can be pushed down to hardware port.
    pub(super) fn is_hardware_filterable(&self, port: &Port) -> bool {
        hardware::device_supported(self, port)
    }

    // Returns `true` if `self` and `pred` are entirely mutually exclusive
    // (i.e., could be correctly represented by "if `a` {} else if `b` {}"...)
    pub(super) fn is_excl(&self, pred: &Predicate) -> bool {
        // Unary predicates at the same layer are mutually exclusive
        // E.g.: `ipv4 | ipv6`, `tcp | udp`
        if self.is_unary() && pred.is_unary() {
            return true;
        }
        // A binary and unary predicate at the same layer will not be mutually excl.
        // E.g.: `ipv4 -> ipv4.src_addr = x.x.x.x` | `ipv4 -> tcp`
        if self.is_unary() != pred.is_unary() {
            return false;
        }

        // Two binary predicates with diff. protocols
        if self.get_protocol() != pred.get_protocol() {
            return false;
        }

        if let Predicate::Binary {
            protocol: _proto,
            field: field_name,
            op,
            value: val,
        } = self
        {
            if let Predicate::Binary {
                protocol: _peer_proto,
                field: peer_field_name,
                op: peer_op,
                value: peer_val,
            } = pred
            {
                // Different fields must be evaluated separately
                if field_name.name() != peer_field_name.name() {
                    return false;
                }

                // Numeric values
                if let Value::Int(v) = val {
                    if let Value::Int(peer_v) = peer_val {
                        return is_excl_int(*v, *v, op, *peer_v, *peer_v, peer_op);
                    }
                    if let Value::IntRange {
                        from: peer_f,
                        to: peer_t,
                    } = peer_val
                    {
                        return is_excl_int(*v, *v, op, *peer_f, *peer_t, peer_op);
                    }
                    return false;
                }
                if let Value::IntRange { from: f, to: t } = val {
                    if let Value::Int(peer_v) = peer_val {
                        return is_excl_int(*f, *t, op, *peer_v, *peer_v, peer_op);
                    }
                    if let Value::IntRange {
                        from: peer_f,
                        to: peer_t,
                    } = peer_val
                    {
                        return is_excl_int(*f, *t, op, *peer_f, *peer_t, peer_op);
                    }
                    return false;
                }

                // IP address
                if let Value::Ipv4(net) = val {
                    if let Value::Ipv4(peer_net) = peer_val {
                        return is_excl_ipv4(net, op, peer_net, peer_op);
                    }
                    return false;
                }
                if let Value::Ipv6(net) = val {
                    if let Value::Ipv6(peer_net) = peer_val {
                        return is_excl_ipv6(net, op, peer_net, peer_op);
                    }
                    return false;
                }

                // Text values
                if let Value::Text(s) = val {
                    if let Value::Text(peer_s) = peer_val {
                        return is_excl_text(s, op, peer_s, peer_op);
                    }
                    return false;
                }

                // Bytes
                if let Value::Byte(b) = val {
                    if let Value::Byte(peer_b) = peer_val {
                        return is_excl_byte(b, op, peer_b, peer_op);
                    }
                    return false;
                }
            }
        }
        false
    }

    // Returns `true` if `self` is a subset of `pred` (`pred` is parent of)
    pub(super) fn is_child(&self, pred: &Predicate) -> bool {
        if self.get_protocol() != pred.get_protocol() {
            return false;
        }

        // Equality should not be considered child_of
        if self == pred {
            return false;
        }

        if self.is_binary() && pred.is_binary() {
            if let Predicate::Binary {
                protocol: _proto,
                field: field_name,
                op,
                value: val,
            } = self
            {
                if let Predicate::Binary {
                    protocol: _parent_proto,
                    field: parent_field_name,
                    op: parent_op,
                    value: parent_val,
                } = pred
                {
                    // Different fields should be checked separately.
                    if field_name.name() != parent_field_name.name() {
                        return false;
                    }

                    // Neq: no concept of a "child"
                    if matches!(parent_op, BinOp::Ne) {
                        return false;
                    }
                    // Except for IPs (which can have netmask),
                    // Eq will not have a child
                    if matches!(parent_op, BinOp::Eq)
                        && (!matches!(parent_val, Value::Ipv4(_))
                            && !matches!(parent_val, Value::Ipv6(_)))
                    {
                        return false;
                    }
                    // != cannot be superset or subset of another operation
                    if matches!(op, BinOp::Ne) || matches!(parent_op, BinOp::Ne) {
                        return false;
                    }
                    // En refers to equality to a variant of a field; these don't have categories
                    if matches!(op, BinOp::En) || matches!(parent_op, BinOp::En) {
                        return false;
                    }
                    // Determining whether a regex is a "subset" of another is more complex than what
                    // we want to do here.
                    //
                    if matches!(op, BinOp::Re) && matches!(parent_op, BinOp::Re) {
                        return false;
                    }

                    // Greater than + less than will not 100% overlap
                    if (matches!(op, BinOp::Ge | BinOp::Gt))
                        && (matches!(parent_op, BinOp::Le | BinOp::Lt))
                    {
                        return false;
                    }
                    if (matches!(parent_op, BinOp::Ge | BinOp::Gt))
                        && (matches!(op, BinOp::Le | BinOp::Lt))
                    {
                        return false;
                    }

                    // Numeric values
                    if let Value::Int(v) = val {
                        if let Value::Int(parent_v) = parent_val {
                            return is_parent_int(*v, *v, op, *parent_v, *parent_v, parent_op);
                        }
                        if let Value::IntRange {
                            from: parent_f,
                            to: parent_t,
                        } = parent_val
                        {
                            return is_parent_int(*v, *v, op, *parent_f, *parent_t, parent_op);
                        }
                        return false;
                    }
                    if let Value::IntRange { from: f, to: t } = val {
                        if let Value::Int(parent_v) = parent_val {
                            return is_parent_int(*f, *t, op, *parent_v, *parent_v, parent_op);
                        }
                        if let Value::IntRange {
                            from: parent_f,
                            to: parent_t,
                        } = parent_val
                        {
                            return is_parent_int(*f, *t, op, *parent_f, *parent_t, parent_op);
                        }
                        return false;
                    }

                    // IP address
                    if let Value::Ipv4(net) = val {
                        if let Value::Ipv4(parent_net) = parent_val {
                            return is_parent_ipv4(net, op, parent_net, parent_op);
                        }
                        return false;
                    }
                    // IPv6 address
                    if let Value::Ipv6(net) = val {
                        if let Value::Ipv6(parent_net) = parent_val {
                            return is_parent_ipv6(net, op, parent_net, parent_op);
                        }
                        return false;
                    }

                    // Text values
                    if let Value::Text(s) = val {
                        if let Value::Text(parent_s) = parent_val {
                            return is_parent_text(s, op, parent_s, parent_op);
                        }
                        return false;
                    }

                    // Bytes
                    if let Value::Byte(b) = val {
                        if let Value::Byte(parent_b) = parent_val {
                            return is_parent_bytes(b, op, parent_b, parent_op);
                        }
                        return false;
                    }
                }
            }
        }

        self.is_binary() && pred.is_unary()
    }
}

pub(super) fn is_excl_ipv4(
    ipv4: &Ipv4Net,
    op: &BinOp,
    peer_ipv4: &Ipv4Net,
    peer_op: &BinOp,
) -> bool {
    match op {
        BinOp::Eq | BinOp::In => {
            match peer_op {
                BinOp::Eq | BinOp::In => {
                    // Mutually exclusive subnets
                    return !peer_ipv4.contains(ipv4) && !ipv4.contains(peer_ipv4);
                }
                BinOp::Ne => {
                    // Same subnet; eq. and neq.
                    return peer_ipv4 == ipv4;
                }
                _ => {}
            }
        }
        BinOp::Ne => match peer_op {
            BinOp::Eq | BinOp::In => {
                return peer_ipv4 == ipv4;
            }
            _ => {}
        },
        _ => {}
    }
    false
}

pub(super) fn is_excl_ipv6(
    ipv6: &Ipv6Net,
    op: &BinOp,
    peer_ipv6: &Ipv6Net,
    peer_op: &BinOp,
) -> bool {
    match op {
        BinOp::Eq | BinOp::In => match peer_op {
            BinOp::Eq | BinOp::In => {
                return !peer_ipv6.contains(ipv6) && !ipv6.contains(peer_ipv6);
            }
            BinOp::Ne => {
                return peer_ipv6 == ipv6;
            }
            _ => {}
        },
        BinOp::Ne => match peer_op {
            BinOp::Eq | BinOp::In => {
                return peer_ipv6 == ipv6;
            }
            _ => {}
        },
        _ => {}
    }
    false
}

pub(super) fn is_excl_text(text: &String, op: &BinOp, peer_text: &String, peer_op: &BinOp) -> bool {
    if matches!(op, BinOp::Eq) && matches!(peer_op, BinOp::Eq) {
        return peer_text != text;
    }
    if (matches!(op, BinOp::Ne) && matches!(peer_op, BinOp::Eq))
        || (matches!(op, BinOp::Eq) && matches!(peer_op, BinOp::Ne))
    {
        return peer_text == text;
    }
    if matches!(op, BinOp::Ne) || matches!(peer_op, BinOp::Ne) {
        // Neq + Neq; Neq + Regex - don't make much sense
        return false;
    }

    if matches!(op, BinOp::Re) && matches!(peer_op, BinOp::Re) {
        // Out of scope
        return false;
    }

    if matches!(op, BinOp::Contains) && matches!(peer_op, BinOp::Eq) {
        return !peer_text.contains(text);
    }
    if matches!(op, BinOp::Eq) && matches!(peer_op, BinOp::Contains) {
        return !text.contains(peer_text);
    }

    if matches!(op, BinOp::Contains) && matches!(peer_op, BinOp::Contains) {
        return false;
    }

    if (matches!(op, BinOp::Ne) && matches!(peer_op, BinOp::Contains))
        || (matches!(op, BinOp::Contains) && matches!(peer_op, BinOp::Ne))
    {
        return false;
    }

    if (matches!(op, BinOp::Re) && matches!(peer_op, BinOp::Contains))
        || (matches!(op, BinOp::Contains) && matches!(peer_op, BinOp::Re))
    {
        return false;
    }

    // Regex + Eq

    let (re, txt) = {
        match matches!(op, BinOp::Re) {
            true => (text, peer_text),
            false => (peer_text, text),
        }
    };
    let regex =
        Regex::new(re).unwrap_or_else(|err| panic!("Invalid Regex string {}: {:?}", re, err));
    !regex.is_match(txt)
}

pub(super) fn is_excl_byte(b: &Vec<u8>, op: &BinOp, peer_b: &Vec<u8>, peer_op: &BinOp) -> bool {
    if matches!(op, BinOp::Eq) && matches!(peer_op, BinOp::Eq) {
        return peer_b != b;
    }
    if (matches!(op, BinOp::Ne) && matches!(peer_op, BinOp::Eq))
        || (matches!(op, BinOp::Eq) && matches!(peer_op, BinOp::Ne))
    {
        return peer_b == b;
    }
    if matches!(op, BinOp::Ne) || matches!(peer_op, BinOp::Ne) {
        // Neq + Neq; Neq + Regex - don't make much sense
        return false;
    }

    if matches!(op, BinOp::Contains) && matches!(peer_op, BinOp::Eq) {
        return memchr::memmem::Finder::new(b).find(peer_b).is_none();
    }
    if matches!(op, BinOp::Eq) && matches!(peer_op, BinOp::Contains) {
        return memchr::memmem::Finder::new(peer_b).find(b).is_none();
    }

    if matches!(op, BinOp::Contains) && matches!(peer_op, BinOp::Contains) {
        return false;
    }

    if (matches!(op, BinOp::Ne) && matches!(peer_op, BinOp::Contains))
        || (matches!(op, BinOp::Contains) && matches!(peer_op, BinOp::Ne))
    {
        return false;
    }
    false
}

pub(super) fn is_parent_ipv4(
    child_ipv4: &Ipv4Net,
    child_op: &BinOp,
    parent_ipv4: &Ipv4Net,
    parent_op: &BinOp,
) -> bool {
    match child_op {
        BinOp::Eq | BinOp::In => {
            if matches!(parent_op, BinOp::Eq) || matches!(parent_op, BinOp::In) {
                return parent_ipv4.contains(child_ipv4);
            }
        }
        BinOp::Ne => {
            if matches!(parent_op, BinOp::Ne) {
                return parent_ipv4.contains(child_ipv4);
            }
        }
        _ => {}
    }
    false
}

pub(super) fn is_parent_ipv6(
    child_ipv6: &Ipv6Net,
    child_op: &BinOp,
    parent_ipv6: &Ipv6Net,
    parent_op: &BinOp,
) -> bool {
    match child_op {
        BinOp::Eq | BinOp::In => {
            if matches!(parent_op, BinOp::Eq | BinOp::In) {
                return parent_ipv6.contains(child_ipv6);
            }
        }
        BinOp::Ne => {
            if matches!(parent_op, BinOp::Ne) {
                return parent_ipv6.contains(child_ipv6);
            }
        }
        _ => {}
    }
    false
}

pub(super) fn is_parent_text(
    child_text: &str,
    child_op: &BinOp,
    parent_text: &str,
    parent_op: &BinOp,
) -> bool {
    if matches!(parent_op, BinOp::Contains)
        && (matches!(child_op, BinOp::Eq) || matches!(child_op, BinOp::Contains))
    {
        return child_text.contains(parent_text);
    }

    if !matches!(parent_op, BinOp::Re) || !matches!(child_op, BinOp::Eq) {
        // Regex overlap is out of scope
        // Regex overlap with != doesn't really make sense
        return false;
    }

    let parent = Regex::new(parent_text)
        .unwrap_or_else(|err| panic!("Invalid Regex string {}: {:?}", parent_text, err));
    parent.is_match(child_text)
}

pub(super) fn is_parent_bytes(
    child_bytes: &[u8],
    child_op: &BinOp,
    parent_bytes: &[u8],
    parent_op: &BinOp,
) -> bool {
    if matches!(parent_op, BinOp::Contains)
        && (matches!(child_op, BinOp::Eq) || matches!(child_op, BinOp::Contains))
    {
        return memchr::memmem::Finder::new(parent_bytes)
            .find(child_bytes)
            .is_some();
    }
    false
}

pub(super) fn is_excl_int(
    from: u64,
    to: u64,
    op: &BinOp,
    peer_from: u64,
    peer_to: u64,
    peer_op: &BinOp,
) -> bool {
    match op {
        BinOp::Eq => {
            match peer_op {
                // E.g., `tcp.port = 80` vs. `tcp.port = 70`
                BinOp::Eq => return from != peer_from,
                // E.g., `tcp.port = 80` vs. `tcp.port != 80`
                BinOp::Ne => return from == peer_from,
                // E.g., `tcp.port = 80` vs. `tcp.port in [70, 79]`
                BinOp::In => return from < peer_from || from > peer_to,
                // E.g., `tcp.port = 80` vs. `tcp.port >= 81`
                BinOp::Ge => return peer_from > from,
                // E.g., `tcp.port = 80` vs. `tcp.port <= 79`
                BinOp::Le => return peer_from < from,
                // E.g., `tcp.port = 80` vs. `tcp.port > 80`
                BinOp::Gt => return peer_from >= from,
                // E.g., `tcp.port = 80` vs. `tcp.port < 80`
                BinOp::Lt => return peer_from <= from,
                _ => {}
            }
        }
        BinOp::Ne => {
            if matches!(peer_op, BinOp::Eq) {
                return from == peer_from;
            }
        }
        BinOp::Ge => {
            match peer_op {
                // E.g., `tcp.port >= 80` and `tcp.port <= 79`
                // E.g., `tcp.port >= 80` and `tcp.port in [70, 79]`
                BinOp::Le | BinOp::In | BinOp::Eq => return from > peer_to,
                // E.g., `tcp.port >= 80` and `tcp.port < 80`
                BinOp::Lt => return from >= peer_from,
                _ => {}
            }
        }
        BinOp::Le => {
            match peer_op {
                // E.g., `tcp.port <= 80` and `tcp.port >= 81`
                BinOp::Ge | BinOp::In | BinOp::Eq => return from < peer_from,
                // E.g., `tcp.port <= 80` and `tcp.port > 80`
                BinOp::Gt => return from <= peer_from,
                _ => {}
            }
        }
        BinOp::Gt => {
            match peer_op {
                // E.g., `tcp.port > 80` and `tcp.port <= 79`
                BinOp::Le | BinOp::In | BinOp::Eq => return from >= peer_to,
                // E.g., `tcp.port > 80` and `tcp.port < 81`
                //       `tcp.port > 80` and `tcp.port < 79`
                BinOp::Lt => return from > peer_from,
                _ => {}
            }
        }
        BinOp::Lt => {
            match peer_op {
                // E.g., `tcp.port < 80` and `tcp.port >= 80`
                //        `tcp.port < 80` and `tcp.port in [80, 100]`
                BinOp::Ge | BinOp::In | BinOp::Eq => return from <= peer_from,
                // E.g., `tcp.port < 80` and `tcp.port > 80`
                BinOp::Gt => return from <= peer_from + 1,
                _ => {}
            }
        }
        BinOp::In => match peer_op {
            BinOp::Eq => return peer_from < from || peer_from > to,
            BinOp::Ge => return peer_from > to,
            BinOp::Gt => return peer_from >= to,
            BinOp::Le => return peer_from < from,
            BinOp::Lt => return peer_from <= from,
            BinOp::In => return peer_to < from || peer_from > to,
            _ => {}
        },
        BinOp::Re | BinOp::En | BinOp::Contains | BinOp::ByteRe | BinOp::NotContains => {}
    }
    false
}

pub(super) fn is_parent_int(
    child_from: u64,
    child_to: u64,
    child_op: &BinOp,
    parent_from: u64,
    parent_to: u64,
    parent_op: &BinOp,
) -> bool {
    match child_op {
        BinOp::Eq | BinOp::In => {
            // E.g., "tcp.port in [80, 100]" is a child of tcp.port >= 80
            //        parent_from (80) <= child_from (80)
            if matches!(parent_op, BinOp::Ge) {
                return parent_from <= child_from;
            }
            // E.g., "tcp = 80" (child_from) is a child of tcp.port > 70 (parent_from)
            if matches!(parent_op, BinOp::Gt) {
                return parent_from < child_from;
            }
            // E.g., "tcp.port in [80, 100]" is a child of tcp.port <= 100
            //        parent_from (100) >= child_to (100)
            if matches!(parent_op, BinOp::Le) {
                return parent_from >= child_to;
            }
            // E.g., "tcp = 80" (child_from) is a child of tcp.port < 100 (parent_from)
            if matches!(parent_op, BinOp::Lt) {
                return parent_from > child_to;
            }
            // E.g., "tcp.port in [80, 100]" is a child of tcp.port in [70, 110]
            //        70 <= 80 and 110 >= 100
            if matches!(parent_op, BinOp::In) {
                return parent_from <= child_from && parent_to >= child_to;
            }
        }
        BinOp::Ge => {
            // E.g., tcp.port >= 80 [child_from] is a child of tcp.port >= 70 [parent_from]
            if matches!(parent_op, BinOp::Ge | BinOp::Gt) {
                return parent_from < child_from;
            }
        }
        BinOp::Le => {
            // E.g., "tcp.port <= 80" [child_from] is a child of "tcp.port <= 81 [parent_from]"
            // \note Matching op and matching value is taken care of.
            if matches!(parent_op, BinOp::Le | BinOp::Lt) {
                return parent_from > child_from;
            }
        }
        BinOp::Gt => {
            // E.g., tcp.port > 80 [child_from] is a child of tcp.port >= 80 [parent_from]
            if matches!(parent_op, BinOp::Gt | BinOp::Ge) {
                return parent_from <= child_from;
            }
        }
        BinOp::Lt => {
            // E.g., tcp.port < 80 [child_from] is a child of tcp.port <= 80 [parent_from]
            if matches!(parent_op, BinOp::Le | BinOp::Lt) {
                return parent_from >= child_from;
            }
        }
        _ => {}
    }
    false
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
    ByteRe,
    Contains,
    NotContains,
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
            BinOp::ByteRe => write!(f, "~b"),
            BinOp::Contains => write!(f, "contains"),
            BinOp::NotContains => write!(f, "not contains"),
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
    Byte(Vec<u8>),
}

impl fmt::Display for Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        match self {
            Value::Int(val) => write!(f, "{}", val),
            Value::IntRange { from, to } => write!(f, "{}..{}", from, to),
            Value::Ipv4(net) => write!(f, "{}", net),
            Value::Ipv6(net) => write!(f, "{}", net),
            Value::Text(val) => write!(f, "{}", val),
            Value::Byte(val) => {
                write!(f, "|")?;
                write!(f, "{}", val.iter().map(|b| format!("{:02X}", b)).join(" "))?;
                write!(f, "|")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn core_ast_req_packet() {
        let pred = Predicate::Binary {
            protocol: protocol!("tcp"),
            field: field!("port"),
            op: BinOp::Eq,
            value: Value::Int(80),
        };
        assert!(!pred.req_packet());
        let pred = Predicate::Binary {
            protocol: protocol!("tcp"),
            field: field!("syn"),
            op: BinOp::Eq,
            value: Value::Int(1),
        };
        assert!(pred.req_packet());
        let pred = Predicate::Unary {
            protocol: protocol!("tcp"),
        };
        assert!(!pred.req_packet());
        let pred = Predicate::Unary {
            protocol: protocol!("ethernet"),
        };
        assert!(pred.req_packet());
    }

    #[test]
    fn core_ast_has_path() {
        assert!(has_path(&protocol!("tcp"), &protocol!("ethernet")));
        assert!(has_path(&protocol!("dns"), &protocol!("ipv6")));
        assert!(has_path(&protocol!("dns"), &protocol!("udp")));
        assert!(has_path(&protocol!("tcp"), &protocol!("ipv4")));
        assert!(!has_path(&protocol!("ipv4"), &protocol!("tcp")));
        assert!(!has_path(&protocol!("ipv4"), &protocol!("ipv4")));
        assert!(!has_path(&protocol!("http"), &protocol!("udp")));
        assert!(has_path(&protocol!("quic"), &protocol!("udp")));
        assert!(!has_path(&protocol!("quic"), &protocol!("dns")));
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
        assert!(tls_unary.on_proto());

        let dns_unary = Predicate::Unary {
            protocol: protocol!("dns"),
        };
        assert!(dns_unary.on_proto());
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

    #[test]
    fn core_is_parent() {
        let ipv4_child = Predicate::Binary {
            protocol: protocol!("ipv4"),
            field: field!("src_addr"),
            op: BinOp::Eq,
            value: Value::Ipv4(Ipv4Net::new(Ipv4Addr::new(10, 10, 0, 0), 16).unwrap()),
        };
        let ipv4_parent = Predicate::Binary {
            protocol: protocol!("ipv4"),
            field: field!("src_addr"),
            op: BinOp::Eq,
            value: Value::Ipv4(Ipv4Net::new(Ipv4Addr::new(10, 0, 0, 0), 8).unwrap()),
        };
        assert!(ipv4_child.is_child(&ipv4_parent));
        assert!(!ipv4_parent.is_child(&ipv4_child));
        // 1.2.1.1/31
        // 1.2.1.23/31
        let ipv4_a = Predicate::Binary {
            protocol: protocol!("ipv4"),
            field: field!("src_addr"),
            op: BinOp::Eq,
            value: Value::Ipv4(Ipv4Net::new(Ipv4Addr::new(1, 2, 1, 1), 31).unwrap()),
        };
        let ipv4_b = Predicate::Binary {
            protocol: protocol!("ipv4"),
            field: field!("src_addr"),
            op: BinOp::Eq,
            value: Value::Ipv4(Ipv4Net::new(Ipv4Addr::new(1, 2, 1, 23), 31).unwrap()),
        };
        assert!(!ipv4_b.is_child(&ipv4_a));
        assert!(!ipv4_a.is_child(&ipv4_b));

        let tcp_80 = Predicate::Binary {
            protocol: protocol!("tcp"),
            field: field!("port"),
            op: BinOp::Eq,
            value: Value::Int(80),
        };
        let tcp_ge_70 = Predicate::Binary {
            protocol: protocol!("tcp"),
            field: field!("port"),
            op: BinOp::Ge,
            value: Value::Int(70),
        };
        assert!(tcp_80.is_child(&tcp_ge_70));
        assert!(!tcp_ge_70.is_child(&tcp_80));

        let tcp_leq_80 = Predicate::Binary {
            protocol: protocol!("tcp"),
            field: field!("port"),
            op: BinOp::Le,
            value: Value::Int(80),
        };
        assert!(tcp_80.is_child(&tcp_leq_80));
        let tcp_lt_80 = Predicate::Binary {
            protocol: protocol!("tcp"),
            field: field!("port"),
            op: BinOp::Lt,
            value: Value::Int(80),
        };
        assert!(!tcp_leq_80.is_child(&tcp_lt_80));
        assert!(tcp_lt_80.is_child(&tcp_leq_80));
        assert!(tcp_80.is_child(&tcp_leq_80));

        let tcp_in_90_100 = Predicate::Binary {
            protocol: protocol!("tcp"),
            field: field!("port"),
            op: BinOp::In,
            value: Value::IntRange { from: 90, to: 100 },
        };
        let tcp_in_80_100 = Predicate::Binary {
            protocol: protocol!("tcp"),
            field: field!("port"),
            op: BinOp::In,
            value: Value::IntRange { from: 80, to: 100 },
        };
        assert!(tcp_in_90_100.is_child(&tcp_in_80_100));
        assert!(!tcp_in_80_100.is_child(&tcp_leq_80));
        assert!(tcp_in_80_100.is_child(&tcp_ge_70));

        let http_unary = Predicate::Unary {
            protocol: protocol!("http"),
        };
        let http_get = Predicate::Binary {
            protocol: protocol!("http"),
            field: field!("method"),
            op: BinOp::Eq,
            value: Value::Text("GET".to_owned()),
        };
        assert!(http_get.is_child(&http_unary));
        let http_get_re = Predicate::Binary {
            protocol: protocol!("http"),
            field: field!("method"),
            op: BinOp::Re,
            value: Value::Text("[A-Z]{3}".to_owned()),
        };
        assert!(http_get.is_child(&http_get_re));

        let ssh_contains_str = Predicate::Binary {
            protocol: protocol!("ssh"),
            field: field!("software_version_ctos"),
            op: BinOp::Contains,
            value: Value::Text("OpenSSH".to_owned()),
        };
        let ssh_eq_str = Predicate::Binary {
            protocol: protocol!("ssh"),
            field: field!("software_version_ctos"),
            op: BinOp::Eq,
            value: Value::Text("OpenSSH_6.7".to_owned()),
        };
        assert!(ssh_eq_str.is_child(&ssh_contains_str));
        assert!(!ssh_contains_str.is_child(&ssh_eq_str));

        let ssh_contains_str2 = Predicate::Binary {
            protocol: protocol!("ssh"),
            field: field!("software_version_ctos"),
            op: BinOp::Contains,
            value: Value::Text("OpenSSH_6.7".to_owned()),
        };
        assert!(!ssh_contains_str.is_child(&ssh_contains_str2));
        assert!(ssh_contains_str2.is_child(&ssh_contains_str));

        let ssh_contains_bytes = Predicate::Binary {
            protocol: protocol!("ssh"),
            field: field!("key_exchange_cookie_stoc"),
            op: BinOp::Contains,
            value: Value::Byte(vec![0x70, 0x65]),
        };
        let ssh_eq_bytes = Predicate::Binary {
            protocol: protocol!("ssh"),
            field: field!("key_exchange_cookie_stoc"),
            op: BinOp::Eq,
            value: Value::Byte(vec![0x4F, 0x70, 0x65, 0x6E]),
        };
        assert!(ssh_eq_bytes.is_child(&ssh_contains_bytes));
        assert!(!ssh_contains_bytes.is_child(&ssh_eq_bytes));

        let ssh_contains_bytes2 = Predicate::Binary {
            protocol: protocol!("ssh"),
            field: field!("key_exchange_cookie_stoc"),
            op: BinOp::Contains,
            value: Value::Byte(vec![0x4F, 0x70, 0x65, 0x6E]),
        };
        assert!(!ssh_contains_bytes.is_child(&ssh_contains_bytes2));
        assert!(ssh_contains_bytes2.is_child(&ssh_contains_bytes));
    }

    #[test]
    fn core_is_excl() {
        let tcp_80 = Predicate::Binary {
            protocol: protocol!("tcp"),
            field: field!("port"),
            op: BinOp::Eq,
            value: Value::Int(80),
        };
        let tcp_ge_81 = Predicate::Binary {
            protocol: protocol!("tcp"),
            field: field!("port"),
            op: BinOp::Ge,
            value: Value::Int(81),
        };
        assert!(tcp_80.is_excl(&tcp_ge_81));
        assert!(tcp_ge_81.is_excl(&tcp_80));

        let tcp_in_70_79 = Predicate::Binary {
            protocol: protocol!("tcp"),
            field: field!("port"),
            op: BinOp::In,
            value: Value::IntRange { from: 70, to: 79 },
        };
        assert!(tcp_80.is_excl(&tcp_in_70_79));
        assert!(tcp_in_70_79.is_excl(&tcp_80));
        assert!(tcp_ge_81.is_excl(&tcp_in_70_79));
        assert!(tcp_in_70_79.is_excl(&tcp_ge_81));

        let tcp_in_90_100 = Predicate::Binary {
            protocol: protocol!("tcp"),
            field: field!("port"),
            op: BinOp::In,
            value: Value::IntRange { from: 90, to: 100 },
        };
        assert!(tcp_80.is_excl(&tcp_in_90_100));
        assert!(tcp_in_90_100.is_excl(&tcp_80));
        assert!(!tcp_in_90_100.is_excl(&tcp_ge_81));
        assert!(!tcp_ge_81.is_excl(&tcp_in_90_100));

        let http_get = Predicate::Binary {
            protocol: protocol!("http"),
            field: field!("method"),
            op: BinOp::Eq,
            value: Value::Text("GET".to_owned()),
        };
        let http_get_re = Predicate::Binary {
            protocol: protocol!("http"),
            field: field!("method"),
            op: BinOp::Re,
            value: Value::Text("[A-Z]{5}".to_owned()),
        };
        assert!(http_get.is_excl(&http_get_re));
        assert!(http_get_re.is_excl(&http_get));

        let http_put = Predicate::Binary {
            protocol: protocol!("http"),
            field: field!("method"),
            op: BinOp::Eq,
            value: Value::Text("PUT".to_owned()),
        };
        assert!(http_get_re.is_excl(&http_put));
        assert!(http_get.is_excl(&http_put));

        let ipv4_a = Predicate::Binary {
            protocol: protocol!("ipv4"),
            field: field!("src_addr"),
            op: BinOp::Eq,
            value: Value::Ipv4(Ipv4Net::new(Ipv4Addr::new(1, 2, 1, 1), 31).unwrap()),
        };
        let ipv4_b = Predicate::Binary {
            protocol: protocol!("ipv4"),
            field: field!("src_addr"),
            op: BinOp::Eq,
            value: Value::Ipv4(Ipv4Net::new(Ipv4Addr::new(1, 2, 1, 23), 31).unwrap()),
        };
        assert!(ipv4_b.is_excl(&ipv4_a));
        assert!(ipv4_a.is_excl(&ipv4_b));

        let ssh_eq_str = Predicate::Binary {
            protocol: protocol!("ssh"),
            field: field!("software_version_ctos"),
            op: BinOp::Eq,
            value: Value::Text("OpenSSH".to_owned()),
        };
        let ssh_contains_str = Predicate::Binary {
            protocol: protocol!("ssh"),
            field: field!("software_version_ctos"),
            op: BinOp::Contains,
            value: Value::Text("OpenSSH_6.7".to_owned()),
        };
        assert!(ssh_eq_str.is_excl(&ssh_contains_str));
        assert!(ssh_contains_str.is_excl(&ssh_eq_str));

        let ssh_eq_str2 = Predicate::Binary {
            protocol: protocol!("ssh"),
            field: field!("software_version_ctos"),
            op: BinOp::Eq,
            value: Value::Text("OpenSSH_6.7".to_owned()),
        };
        let ssh_contains_str2 = Predicate::Binary {
            protocol: protocol!("ssh"),
            field: field!("software_version_ctos"),
            op: BinOp::Contains,
            value: Value::Text("OpenSSH".to_owned()),
        };
        assert!(!ssh_eq_str2.is_excl(&ssh_contains_str2));
        assert!(!ssh_contains_str2.is_excl(&ssh_eq_str2));

        let ssh_eq_byte = Predicate::Binary {
            protocol: protocol!("ssh"),
            field: field!("key_exchange_cookie_stoc"),
            op: BinOp::Eq,
            value: Value::Byte(vec![0x4F, 0x70, 0x65, 0x6E]),
        };
        let ssh_contains_byte = Predicate::Binary {
            protocol: protocol!("ssh"),
            field: field!("key_exchange_cookie_stoc"),
            op: BinOp::Contains,
            value: Value::Byte(vec![0x70, 0x65, 0x6E]),
        };
        assert!(!ssh_eq_byte.is_excl(&ssh_contains_byte));
        assert!(!ssh_contains_byte.is_excl(&ssh_eq_byte));

        let ssh_eq_byte2 = Predicate::Binary {
            protocol: protocol!("ssh"),
            field: field!("key_exchange_cookie_stoc"),
            op: BinOp::Eq,
            value: Value::Byte(vec![0x65, 0x6E]),
        };
        assert!(ssh_eq_byte2.is_excl(&ssh_contains_byte));
        assert!(ssh_contains_byte.is_excl(&ssh_eq_byte2));
    }
}
