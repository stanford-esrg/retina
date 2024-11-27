//! Utilities for compile-time filter generation and subscription handling.
//!
//! This module's exports will be most relevant for those adding new filter utilities
//! and/or datatypes. Nothing in this module is needed for writing an ordinary
//! Retina application.
//!

pub mod actions;
pub use actions::{ActionData, Actions};

#[doc(hidden)]
#[macro_use]
pub mod macros;
#[doc(hidden)]
pub mod ast;
mod hardware;
#[allow(clippy::upper_case_acronyms)]
mod parser;
mod pattern;
#[doc(hidden)]
pub mod ptree;
#[doc(hidden)]
pub mod ptree_flat;

pub mod datatypes;
pub use datatypes::{DataType, Level, SubscriptionSpec};

use crate::filter::hardware::{flush_rules, HardwareFilter};
use crate::filter::parser::FilterParser;
use crate::filter::pattern::{FlatPattern, LayeredPattern};
use crate::filter::ptree_flat::FlatPTree;
use crate::lcore::CoreId;
use crate::memory::mbuf::Mbuf;
use crate::port::Port;
use crate::protocols::stream::{ConnData, Session};
use crate::subscription::Trackable;

use std::fmt;

use anyhow::{bail, Result};
use thiserror::Error;

// Filter functions
// Note: Rust won't enforce trait bounds on type alias, but T must implement Tracked.

/// Software filter applied to each packet. Will drop, deliver, and/or
/// forward packets to the connection manager. If hardware assist is enabled,
/// the framework will additionally attempt to install the filter in the NICs.
pub type PacketContFn = fn(&Mbuf, &CoreId) -> Actions;
/// Filter applied to the first packet of a connection to initialize actions.
pub type PacketFilterFn<T> = fn(&Mbuf, &T) -> Actions;
/// Filter applied when the application-layer protocol is identified.
/// This may drop connections or update actions.
/// It may also drain buffered packets to packet-level subscriptions that match
/// at the protocol stage.
pub type ProtoFilterFn<T> = fn(&ConnData, &T) -> Actions;
/// Filter applied when the application-layer session is parsed.
/// This may drop connections, drop sessions, or update actions.
/// It may also deliver session-level subscriptions.
pub type SessionFilterFn<T> = fn(&Session, &ConnData, &T) -> Actions;
/// Filter applied to disambiguate and deliver matched packet-level subscriptions
/// that required stateful filtering (i.e., could not be delivered at the packet stage).
pub type PacketDeliverFn<T> = fn(&Mbuf, &ConnData, &T);
/// Filter applied to disambiguate and deliver matched connection-level subscriptions
/// (those delivered at connection termination).
pub type ConnDeliverFn<T> = fn(&ConnData, &T);

#[doc(hidden)]
pub struct FilterFactory<T>
where
    T: Trackable,
{
    pub filter_str: String,
    pub packet_continue: PacketContFn,
    pub packet_filter: PacketFilterFn<T>,
    pub proto_filter: ProtoFilterFn<T>,
    pub session_filter: SessionFilterFn<T>,
    pub packet_deliver: PacketDeliverFn<T>,
    pub conn_deliver: ConnDeliverFn<T>,
}

impl<T> FilterFactory<T>
where
    T: Trackable,
{
    pub fn new(
        filter_str: &str,
        packet_continue: PacketContFn,
        packet_filter: PacketFilterFn<T>,
        proto_filter: ProtoFilterFn<T>,
        session_filter: SessionFilterFn<T>,
        packet_deliver: PacketDeliverFn<T>,
        conn_deliver: ConnDeliverFn<T>,
    ) -> Self {
        FilterFactory {
            filter_str: filter_str.to_string(),
            packet_continue,
            packet_filter,
            proto_filter,
            session_filter,
            packet_deliver,
            conn_deliver,
        }
    }
}

#[derive(Default, Debug, Clone)]
pub struct Filter {
    patterns: Vec<LayeredPattern>,
}

impl Filter {
    pub fn new(filter_raw: &str) -> Result<Filter> {
        let raw_patterns = FilterParser::parse_filter(filter_raw)?;

        let flat_patterns = raw_patterns
            .into_iter()
            .map(|p| FlatPattern { predicates: p })
            .collect::<Vec<_>>();

        let mut fq_patterns = vec![];
        for pattern in flat_patterns.iter() {
            fq_patterns.extend(pattern.to_fully_qualified()?);
        }

        // deduplicate fully qualified patterns
        fq_patterns.sort();
        fq_patterns.dedup();

        // prune redundant branches
        let flat_patterns: Vec<_> = fq_patterns.iter().map(|p| p.to_flat_pattern()).collect();

        let mut ptree = FlatPTree::new(&flat_patterns);
        ptree.prune_branches();

        Ok(Filter {
            patterns: ptree.to_layered_patterns(),
        })
    }

    // Returns disjunct of layered patterns
    pub fn get_patterns_layered(&self) -> Vec<LayeredPattern> {
        self.patterns.clone()
    }

    // Returns disjuct of flat patterns
    pub fn get_patterns_flat(&self) -> Vec<FlatPattern> {
        self.patterns
            .iter()
            .map(|p| p.to_flat_pattern())
            .collect::<Vec<_>>()
    }

    // Returns predicate tree
    pub fn to_ptree(&self) -> FlatPTree {
        FlatPTree::new(&self.get_patterns_flat())
    }

    // Returns `true` if filter can be completely realized in hardware
    pub fn is_hardware_filterable(&self) -> bool {
        // needs to take port as argument
        todo!();
    }

    pub(crate) fn set_hardware_filter(&self, port: &Port) -> Result<()> {
        let hw_filter = HardwareFilter::new(self, port);
        match hw_filter.install() {
            Ok(_) => Ok(()),
            Err(error) => {
                flush_rules(port);
                bail!(error);
            }
        }
    }
}

impl fmt::Display for Filter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "[Filter]: ")?;
        for pattern in self.patterns.iter() {
            writeln!(f, "{}", pattern.to_flat_pattern())?;
        }
        Ok(())
    }
}

#[derive(Error, Debug)]
pub enum FilterError {
    // Catches all filters that do not satisfy the grammar.
    // This is an umbrella error type that covers some of the
    // more specific errors below as well.
    #[error("Invalid filter format")]
    InvalidFormat,

    #[error("Invalid pattern. Contains unsupported layer encapsulation: {0}")]
    InvalidPatternLayers(FlatPattern),

    #[error("Invalid predicate type: {0}")]
    InvalidPredType(String),

    #[error("Invalid header: {0}")]
    InvalidHeader(String),

    #[error("Invalid field: {0}")]
    InvalidField(String),

    #[error("Invalid binary comparison op: {0}")]
    InvalidBinOp(String),

    #[error("Invalid RHS type for predicate: {0}")]
    InvalidRhsType(String),

    #[error("Invalid RHS value for predicate: {0}")]
    InvalidRhsValue(String),

    #[error("Invalid Integer")]
    InvalidInt {
        #[from]
        source: std::num::ParseIntError,
    },

    #[error("Invalid Range: {start}..{end}")]
    InvalidIntRange { start: u64, end: u64 },

    #[error("Invalid Address")]
    InvalidAddress {
        #[from]
        source: std::net::AddrParseError,
    },

    #[error("Invalid Prefix Len")]
    InvalidPrefixLen {
        #[from]
        source: ipnet::PrefixLenError,
    },
}

// Nice-to-have: tests for filter string parsing
