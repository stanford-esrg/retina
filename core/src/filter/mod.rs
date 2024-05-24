pub mod actions;
pub use actions::{Actions, ActionFlags, ActionData, PacketActions, Packet};

pub mod actions_parse;
pub use actions_parse::{ConfigRaw, SubscriptionSpec};

#[macro_use]
pub mod macros;
pub mod ast;
mod hardware;
#[allow(clippy::upper_case_acronyms)]
mod parser;
mod pattern;
pub mod ptree_flat;
pub mod ptree;

use crate::filter::hardware::{flush_rules, HardwareFilter};
use crate::filter::parser::FilterParser;
use crate::filter::pattern::{FlatPattern, LayeredPattern};
use crate::filter::ptree_flat::FlatPTree;
use crate::filter::ptree::{PTree, FilterType};
use crate::memory::mbuf::Mbuf;
use crate::port::Port;
use crate::protocols::stream::{ConnData, Session};
use crate::subscription::Trackable;

use std::fmt;

use anyhow::{bail, Result};
use thiserror::Error;

/// Filter types
pub type PacketContFn = fn(&Mbuf) -> PacketActions;
pub type PacketFilterFn = fn(&Mbuf) -> Actions;
pub type ConnFilterFn = fn(&ConnData) -> Actions;
pub type SessionFilterFn = fn(&Session, &ConnData) -> Actions;

// Subscription deliver functions
// \note Rust won't enforce trait bounds on type alias
pub type PacketDeliverFn = fn(&Mbuf);
pub type ConnDeliverFn<T> = fn(&ConnData, &T);
pub type SessionDeliverFn<T> = fn(std::rc::Rc<Session>, &ConnData, &T);

pub struct FilterFactory<T>
where 
    T: Trackable
{
    pub filter_str: String,
    pub protocol_str: String,
    pub packet_continue: PacketContFn,
    pub packet_filter: PacketFilterFn,
    pub conn_filter: ConnFilterFn,
    pub session_filter: SessionFilterFn,
    pub packet_deliver: PacketDeliverFn,
    pub conn_deliver: ConnDeliverFn<T>,
    pub session_deliver: SessionDeliverFn<T>,
}

impl<T> FilterFactory<T>
where
    T: Trackable
{
    pub fn new(
        filter_str: &str,
        protocol_str: &str,
        packet_continue: PacketContFn,
        packet_filter: PacketFilterFn,
        conn_filter: ConnFilterFn,
        session_filter: SessionFilterFn,
        packet_deliver: PacketDeliverFn,
        conn_deliver: ConnDeliverFn<T>,
        session_deliver: SessionDeliverFn<T>
    ) -> Self {
        FilterFactory {
            filter_str: filter_str.to_string(),
            protocol_str: protocol_str.to_string(),
            packet_continue,
            packet_filter,
            conn_filter,
            session_filter,
            packet_deliver, 
            conn_deliver, 
            session_deliver
        }
    }
}

#[derive(Default, Debug, Clone)]
pub struct Filter {
    patterns: Vec<LayeredPattern>,
}

impl Filter {
    pub fn from_str(filter_raw: &str) -> Result<Filter> {
        let parser = FilterParser { split_combined: true /* TODOTR */ };
        let raw_patterns = parser.parse_filter(filter_raw)?;

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

    pub fn new(filter_raw: &str, filter_type: FilterType, 
               actions: &Actions, filter_id: usize) -> Result<Filter> {
        let parser = FilterParser { split_combined: true /* TODOTR */ };
        let raw_patterns = parser.parse_filter(filter_raw)?;

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
        let mut ptree = PTree::new(&flat_patterns, filter_type, actions, filter_id);

        ptree.prune_branches();

        Ok(Filter {
            patterns: ptree.to_layered_patterns(),
        })
    }

    /// Returns disjunct of layered patterns
    pub fn get_patterns_layered(&self) -> Vec<LayeredPattern> {
        self.patterns.clone()
    }

    /// Returns disjuct of flat patterns
    pub fn get_patterns_flat(&self) -> Vec<FlatPattern> {
        self.patterns
            .iter()
            .map(|p| p.to_flat_pattern())
            .collect::<Vec<_>>()
    }

    /// Returns predicate tree
    pub fn to_ptree(&self) -> FlatPTree {
        FlatPTree::new(&self.get_patterns_flat())
    }

    /// Returns `true` if filter can be completely realized in hardware
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

    #[error("Invalid pattern. Contains duplicate fields: {0}")]
    InvalidPatternDupFields(FlatPattern),

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

#[cfg(test)]
mod tests {
    // use super::*;

    // TODO: test filter string parsing
}
