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
pub struct FilterParser;

impl FilterParser {
    /// Parses filter string as a disjunct of `RawPattern`s
    pub(crate) fn parse_filter(filter_raw: &str) -> Result<Vec<RawPattern>> {
        let ast = FilterParser::parse_as_ast(filter_raw)?;
        Ok(FilterParser::flatten_disjunct(ast))
    }

    fn parse_as_ast(filter_raw: &str) -> Result<Node> {
        let pairs = FilterParser::parse(Rule::filter, filter_raw);
        match pairs {
            Ok(mut pairs) => {
                let pair = pairs.next().unwrap();
                FilterParser::parse_disjunct(pair)
            }
            Err(_) => bail!(FilterError::InvalidFormat),
        }
    }

    // returns a vector of flattened conjuncts (conjunct of predicates)
    fn flatten_disjunct(disjunct: Node) -> Vec<RawPattern> {
        let mut flat_conjuncts: Vec<RawPattern> = vec![];
        if let Node::Disjunct(conjuncts) = disjunct {
            for conjunct in conjuncts {
                let mut flat_conjunct = FilterParser::flatten_conjunct(conjunct);
                flat_conjuncts.append(&mut flat_conjunct)
            }
        }
        flat_conjuncts
    }

    // returns a vector of RawPatterns
    fn flatten_conjunct(conjunct: Node) -> Vec<RawPattern> {
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
                            FilterParser::flatten_disjunct(Node::Disjunct(disjunct));
                        let cur = flat_conjuncts.clone();
                        flat_conjuncts.clear();
                        for conj in flat_disjunct.iter() {
                            for flat_conj in cur.iter() {
                                flat_conjuncts.push(FilterParser::combine(flat_conj, conj));
                            }
                        }
                    }
                    _ => panic!("Conjunct contains non-predicate or disjunct"),
                }
            }
        }
        flat_conjuncts
    }

    fn parse_disjunct(pair: Pair<Rule>) -> Result<Node> {
        //println!("building from expr: {:#?}", pair);
        let inner = pair.into_inner();
        let mut terms = vec![];
        for pair in inner {
            if let Rule::sub_expr = pair.as_rule() {
                terms.push(FilterParser::parse_conjunct(pair)?);
            }
        }
        Ok(Node::Disjunct(terms))
    }

    fn parse_conjunct(pair: Pair<Rule>) -> Result<Node> {
        //println!("building from disjunct: {:#?}", pair);
        let inner = pair.into_inner();
        let mut terms = vec![];
        for pair in inner {
            match pair.as_rule() {
                Rule::expr => terms.push(FilterParser::parse_disjunct(pair)?),
                Rule::predicate => terms.extend(FilterParser::parse_predicate(pair)?),
                _ => (),
            }
        }
        Ok(Node::Conjunct(terms))
    }

    fn parse_predicate(pair: Pair<Rule>) -> Result<Vec<Node>> {
        let mut inner = pair.into_inner();
        let protocol = inner.next().unwrap();
        match inner.next() {
            Some(field) => {
                let op = inner.next().unwrap();
                let value = inner.next().unwrap();

                match field.as_rule() {
                    Rule::field => Ok(vec![Node::Predicate(Predicate::Binary {
                        protocol: FilterParser::parse_protocol(protocol),
                        field: FilterParser::parse_field(field),
                        op: FilterParser::parse_binop(op)?,
                        value: FilterParser::parse_value(value)?,
                    })]),
                    Rule::combined_field => {
                        let mut src_field = "src_".to_owned();
                        src_field.push_str(field.as_str());
                        let op = FilterParser::parse_binop(op.clone())?;
                        let src_node = Node::Predicate(Predicate::Binary {
                            protocol: FilterParser::parse_protocol(protocol.clone()),
                            field: FieldName(src_field),
                            op,
                            value: FilterParser::parse_value(value.clone())?,
                        });

                        let mut dst_field = "dst_".to_owned();
                        dst_field.push_str(field.as_str());
                        let dst_node = Node::Predicate(Predicate::Binary {
                            protocol: FilterParser::parse_protocol(protocol.clone()),
                            field: FieldName(dst_field),
                            op,
                            value: FilterParser::parse_value(value.clone())?,
                        });
                        match op {
                            BinOp::Ne => {
                                // && condition
                                // e.g., "tcp.port != 80" -> tcp.src_port != 80 and tcp.dst_port != 80"
                                Ok(vec![src_node, dst_node])
                            }
                            _ => {
                                // || condition
                                // e.g., "tcp.port = 80" -> tcp.src_port = 80 or tcp.dst_port = 80"
                                // e.g., "tcp.port > 80" -> tcp.src_port > 80 or tcp.dst_port > 80"
                                let terms = vec![
                                    Node::Conjunct(vec![src_node]),
                                    Node::Conjunct(vec![dst_node]),
                                ];
                                Ok(vec![Node::Disjunct(terms)])
                            }
                        }
                    }
                    _ => bail!(FilterError::InvalidFormat),
                }
            }
            None => Ok(vec![Node::Predicate(Predicate::Unary {
                protocol: FilterParser::parse_protocol(protocol),
            })]),
        }
    }

    fn parse_protocol(pair: Pair<Rule>) -> ProtocolName {
        protocol!(pair.as_str())
    }

    fn parse_field(pair: Pair<Rule>) -> FieldName {
        field!(pair.as_str())
    }

    fn parse_binop(pair: Pair<Rule>) -> Result<BinOp> {
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
            Rule::byte_re_op => Ok(BinOp::ByteRe),
            Rule::contains_op => Ok(BinOp::Contains),
            Rule::not_contains_op => Ok(BinOp::NotContains),
            _ => bail!(FilterError::InvalidBinOp(op_str)),
        }
    }

    fn parse_value(pair: Pair<Rule>) -> Result<Value> {
        let pair_str = pair.as_str().to_string();
        let rhs = pair.into_inner().next().unwrap();
        match rhs.as_rule() {
            Rule::ipv4_lit => {
                let ipnet = FilterParser::parse_ipv4(rhs.into_inner())?;
                Ok(Value::Ipv4(ipnet))
            }
            Rule::ipv6_lit => {
                let ipnet = FilterParser::parse_ipv6(rhs.into_inner())?;
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
                let range = FilterParser::parse_int_range(rhs.into_inner())?;
                Ok(Value::IntRange {
                    from: *range.start(),
                    to: *range.end(),
                })
            }
            Rule::byte_lit => {
                let bytes_as_str = rhs.as_str();
                let bytes_vec = bytes_as_str
                    .replace("|", "")
                    .split_whitespace()
                    .map(|s| {
                        u8::from_str_radix(s, 16).unwrap_or_else(|err| {
                            panic!("Failed to parse {} in {}: {:?}", s, bytes_as_str, err)
                        })
                    })
                    .collect();
                Ok(Value::Byte(bytes_vec))
            }
            _ => bail!(FilterError::InvalidRhsType(pair_str)),
        }
    }

    fn parse_ipv4(mut ipv4_lit: Pairs<Rule>) -> Result<Ipv4Net> {
        let ipv4_addr = ipv4_lit.next().unwrap();
        let ip = Ipv4Addr::from_str(ipv4_addr.as_str())?;
        if let Some(ipv4_prefix) = ipv4_lit.next() {
            let prefix = ipv4_prefix.as_str().parse::<u8>()?;
            Ok(Ipv4Net::new(ip, prefix)?)
        } else {
            Ok(Ipv4Net::new(ip, 32)?)
        }
    }

    fn parse_ipv6(mut ipv6_lit: Pairs<Rule>) -> Result<Ipv6Net> {
        let ipv6_addr = ipv6_lit.next().unwrap();
        let ip = Ipv6Addr::from_str(ipv6_addr.as_str())?;
        if let Some(ipv6_prefix) = ipv6_lit.next() {
            let prefix = ipv6_prefix.as_str().parse::<u8>()?;
            Ok(Ipv6Net::new(ip, prefix)?)
        } else {
            Ok(Ipv6Net::new(ip, 128)?)
        }
    }

    fn parse_int_range(mut int_range: Pairs<Rule>) -> Result<RangeInclusive<u64>> {
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
    fn combine(conj1: &[Predicate], conj2: &[Predicate]) -> Vec<Predicate> {
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
