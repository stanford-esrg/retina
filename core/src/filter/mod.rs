#[macro_use]
pub mod macros;
pub mod ast;
mod hardware;
#[allow(clippy::upper_case_acronyms)]
mod parser;
mod pattern;
pub mod ptree;

use crate::filter::hardware::{flush_rules, HardwareFilter};
use crate::filter::parser::FilterParser;
use crate::filter::pattern::{FlatPattern, LayeredPattern};
use crate::filter::ptree::PTree;
use crate::memory::mbuf::Mbuf;
use crate::port::Port;
use crate::protocols::stream::{ConnData, Session};

use std::fmt;

use anyhow::{bail, Result};
use thiserror::Error;

pub type PacketFilterFn = fn(&Mbuf) -> FilterResult;
pub type ConnFilterFn = fn(&ConnData) -> FilterResult;
pub type SessionFilterFn = fn(&Session, usize) -> bool;

/// Represents the result of an intermediate filter.
#[derive(Debug)]
pub enum FilterResult {
    /// Matches a terminal pattern in the filter.
    MatchTerminal(usize),
    /// Matches sub-filter, but non-terminal.
    MatchNonTerminal(usize),
    /// Matches none of the patterns in the filter.
    NoMatch,
}

pub struct FilterFactory {
    pub filter_str: String,
    pub packet_filter: PacketFilterFn,
    pub conn_filter: ConnFilterFn,
    pub session_filter: SessionFilterFn,
}

impl FilterFactory {
    pub fn new(
        filter_str: &str,
        packet_filter: PacketFilterFn,
        conn_filter: ConnFilterFn,
        session_filter: SessionFilterFn,
    ) -> FilterFactory {
        FilterFactory {
            filter_str: filter_str.to_string(),
            packet_filter,
            conn_filter,
            session_filter,
        }
    }
}

#[derive(Default, Debug, Clone)]
pub struct Filter {
    patterns: Vec<LayeredPattern>,
}

impl Filter {
    pub fn from_str(filter_raw: &str, split_combined: bool) -> Result<Filter> {
        let parser = FilterParser { split_combined };
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
        let mut ptree = PTree::new(&flat_patterns);
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
    pub fn to_ptree(&self) -> PTree {
        PTree::new(&self.get_patterns_flat())
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
