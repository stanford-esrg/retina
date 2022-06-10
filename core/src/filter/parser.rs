use super::ast::*;
use crate::filter::FilterError;

use ipnet::{Ipv4Net, Ipv6Net};
use pest::iterators::{Pair, Pairs};
use pest::Parser;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::ops::RangeInclusive;
use std::str::FromStr;

use anyhow::{bail, Result};

#[derive(Parser)]
#[grammar = "filter/grammar.pest"]
pub struct FilterParser {
    /// When `true`, split combined fields `addr` and `port` into a disjunct of
    /// `src_addr or dst_addr` and `src_port or dst_port`.
    pub(crate) split_combined: bool,
}

impl FilterParser {
    /// Parses filter string as a disjunct of `RawPattern`s
    pub(crate) fn parse_filter(&self, filter_raw: &str) -> Result<Vec<RawPattern>> {
        let ast = self.parse_as_ast(filter_raw)?;
        Ok(self.flatten_disjunct(ast))
    }

    fn parse_as_ast(&self, filter_raw: &str) -> Result<Node> {
        let pairs = FilterParser::parse(Rule::filter, filter_raw);
        match pairs {
            Ok(mut pairs) => {
                let pair = pairs.next().unwrap();
                self.parse_disjunct(pair)
            }
            Err(_) => bail!(FilterError::InvalidFormat),
        }
    }

    // returns a vector of flattened conjuncts (conjunct of predicates)
    fn flatten_disjunct(&self, disjunct: Node) -> Vec<RawPattern> {
        let mut flat_conjuncts: Vec<RawPattern> = vec![];
        if let Node::Disjunct(conjuncts) = disjunct {
            for conjunct in conjuncts {
                let mut flat_conjunct = self.flatten_conjunct(conjunct);
                flat_conjuncts.append(&mut flat_conjunct)
            }
        }
        flat_conjuncts
    }

    // returns a vector of RawPatterns
    fn flatten_conjunct(&self, conjunct: Node) -> Vec<RawPattern> {
        let mut flat_conjuncts: Vec<RawPattern> = vec![vec![]];

        if let Node::Conjunct(terms) = conjunct {
            for term in terms {
                match term {
                    Node::Predicate(predicate) => {
                        // append Predicate to end of each flat conjunct
                        for flat_conj in flat_conjuncts.iter_mut() {
                            flat_conj.push(predicate.clone());
                        }
                    }
                    Node::Disjunct(disjunct) => {
                        let flat_disjunct: Vec<RawPattern> =
                            self.flatten_disjunct(Node::Disjunct(disjunct));
                        let cur = flat_conjuncts.clone();
                        flat_conjuncts.clear();
                        for conj in flat_disjunct.iter() {
                            for flat_conj in cur.iter() {
                                flat_conjuncts.push(self.combine(flat_conj, conj));
                            }
                        }
                    }
                    _ => panic!("Conjunct contains non-predicate or disjunct"),
                }
            }
        }
        flat_conjuncts
    }

    fn parse_disjunct(&self, pair: Pair<Rule>) -> Result<Node> {
        //println!("building from expr: {:#?}", pair);
        let inner = pair.into_inner();
        let mut terms = vec![];
        for pair in inner {
            if let Rule::sub_expr = pair.as_rule() {
                terms.push(self.parse_conjunct(pair)?);
            }
        }
        Ok(Node::Disjunct(terms))
    }

    fn parse_conjunct(&self, pair: Pair<Rule>) -> Result<Node> {
        //println!("building from disjunct: {:#?}", pair);
        let inner = pair.into_inner();
        let mut terms = vec![];
        for pair in inner {
            match pair.as_rule() {
                Rule::expr => terms.push(self.parse_disjunct(pair)?),
                Rule::predicate => terms.push(self.parse_predicate(pair)?),
                _ => (),
            }
        }
        Ok(Node::Conjunct(terms))
    }

    fn parse_predicate(&self, pair: Pair<Rule>) -> Result<Node> {
        let mut inner = pair.into_inner();
        let protocol = inner.next().unwrap();
        match inner.next() {
            Some(field) => {
                let op = inner.next().unwrap();
                let value = inner.next().unwrap();

                match field.as_rule() {
                    Rule::field => Ok(Node::Predicate(Predicate::Binary {
                        protocol: self.parse_protocol(protocol),
                        field: self.parse_field(field),
                        op: self.parse_binop(op)?,
                        value: self.parse_value(value)?,
                    })),
                    Rule::combined_field => {
                        if self.split_combined {
                            let mut src_field = "src_".to_owned();
                            src_field.push_str(field.as_str());
                            let src_node = Node::Predicate(Predicate::Binary {
                                protocol: self.parse_protocol(protocol.clone()),
                                field: FieldName(src_field),
                                op: self.parse_binop(op.clone())?,
                                value: self.parse_value(value.clone())?,
                            });

                            let mut dst_field = "dst_".to_owned();
                            dst_field.push_str(field.as_str());
                            let dst_node = Node::Predicate(Predicate::Binary {
                                protocol: self.parse_protocol(protocol.clone()),
                                field: FieldName(dst_field),
                                op: self.parse_binop(op.clone())?,
                                value: self.parse_value(value.clone())?,
                            });

                            let terms = vec![
                                Node::Conjunct(vec![src_node]),
                                Node::Conjunct(vec![dst_node]),
                            ];
                            Ok(Node::Disjunct(terms))
                        } else {
                            Ok(Node::Predicate(Predicate::Binary {
                                protocol: self.parse_protocol(protocol),
                                field: self.parse_field(field),
                                op: self.parse_binop(op)?,
                                value: self.parse_value(value)?,
                            }))
                        }
                    }
                    _ => bail!(FilterError::InvalidFormat),
                }
            }
            None => Ok(Node::Predicate(Predicate::Unary {
                protocol: self.parse_protocol(protocol),
            })),
        }
    }

    fn parse_protocol(&self, pair: Pair<Rule>) -> ProtocolName {
        protocol!(pair.as_str())
    }

    fn parse_field(&self, pair: Pair<Rule>) -> FieldName {
        field!(pair.as_str())
    }

    fn parse_binop(&self, pair: Pair<Rule>) -> Result<BinOp> {
        let op_str = pair.as_str().to_string();
        let mut inner = pair.into_inner();
        match inner.next().unwrap().as_rule() {
            Rule::eq_op => Ok(BinOp::Eq),
            Rule::ne_op => Ok(BinOp::Ne),
            Rule::ge_op => Ok(BinOp::Ge),
            Rule::le_op => Ok(BinOp::Le),
            Rule::gt_op => Ok(BinOp::Gt),
            Rule::lt_op => Ok(BinOp::Lt),
            Rule::in_op => Ok(BinOp::In),
            Rule::re_op => Ok(BinOp::Re),
            Rule::en_op => Ok(BinOp::En),
            _ => bail!(FilterError::InvalidBinOp(op_str)),
        }
    }

    fn parse_value(&self, pair: Pair<Rule>) -> Result<Value> {
        let pair_str = pair.as_str().to_string();
        let rhs = pair.into_inner().next().unwrap();
        match rhs.as_rule() {
            Rule::ipv4_lit => {
                let ipnet = self.parse_ipv4(rhs.into_inner())?;
                Ok(Value::Ipv4(ipnet))
            }
            Rule::ipv6_lit => {
                let ipnet = self.parse_ipv6(rhs.into_inner())?;
                Ok(Value::Ipv6(ipnet))
            }
            Rule::int_lit => {
                let val = rhs.as_str().parse::<u64>()?;
                Ok(Value::Int(val))
            }
            Rule::text => {
                // str_lit is a silent rule, parses directly to Rule::text
                Ok(Value::Text(rhs.as_str().to_owned()))
            }
            Rule::int_range => {
                let range = self.parse_int_range(rhs.into_inner())?;
                Ok(Value::IntRange {
                    from: *range.start(),
                    to: *range.end(),
                })
            }
            _ => bail!(FilterError::InvalidRhsType(pair_str)),
        }
    }

    fn parse_ipv4(&self, mut ipv4_lit: Pairs<Rule>) -> Result<Ipv4Net> {
        let ipv4_addr = ipv4_lit.next().unwrap();
        let ip = Ipv4Addr::from_str(ipv4_addr.as_str())?;
        if let Some(ipv4_prefix) = ipv4_lit.next() {
            let prefix = ipv4_prefix.as_str().parse::<u8>()?;
            Ok(Ipv4Net::new(ip, prefix)?)
        } else {
            Ok(Ipv4Net::new(ip, 32)?)
        }
    }

    fn parse_ipv6(&self, mut ipv6_lit: Pairs<Rule>) -> Result<Ipv6Net> {
        let ipv6_addr = ipv6_lit.next().unwrap();
        let ip = Ipv6Addr::from_str(ipv6_addr.as_str())?;
        if let Some(ipv6_prefix) = ipv6_lit.next() {
            let prefix = ipv6_prefix.as_str().parse::<u8>()?;
            Ok(Ipv6Net::new(ip, prefix)?)
        } else {
            Ok(Ipv6Net::new(ip, 128)?)
        }
    }

    fn parse_int_range(&self, mut int_range: Pairs<Rule>) -> Result<RangeInclusive<u64>> {
        let start = int_range.next().unwrap().as_str().parse::<u64>()?;
        let end = int_range.next().unwrap().as_str().parse::<u64>()?;

        // disallow same start and end
        if start >= end {
            bail!(FilterError::InvalidIntRange { start, end })
        } else {
            Ok(RangeInclusive::<u64>::new(start, end))
        }
    }

    // helper function to combine conj1 and conj2, returns new vector of Predicates
    fn combine(&self, conj1: &[Predicate], conj2: &[Predicate]) -> Vec<Predicate> {
        let mut result = vec![];
        for predicate in conj1 {
            result.push(predicate.clone());
        }
        for predicate in conj2 {
            result.push(predicate.clone())
        }
        result
    }
}

// A RawPattern is a conjunct of predicates to satisfy
pub type RawPattern = Vec<Predicate>;

#[derive(Debug, Clone, PartialEq, Eq)]
enum Node {
    Predicate(Predicate),
    Disjunct(Vec<Node>),
    Conjunct(Vec<Node>),
}
