//! DNS transaction components.

use dns_parser::rdata::{Aaaa, RData, A};
use dns_parser::{Packet, ResponseCode};

use serde::Serialize;

/// A DNS Query.
#[derive(Debug, Serialize)]
pub struct DnsQuery {
    pub num_questions: u16,
    pub recursion_desired: bool, // appears in query & answer
    pub queries: Vec<String>,    // typically only one question per query, could have multiple
}

impl DnsQuery {
    pub(super) fn parse_query(pkt: &Packet) -> Self {
        let mut queries = Vec::new();
        for q in &pkt.questions {
            log::debug!("  query: {}/{:?}", q.qname, q.qtype);
            queries.push(q.qname.to_string());
        }
        DnsQuery {
            num_questions: pkt.header.questions,
            recursion_desired: pkt.header.recursion_desired,
            queries,
        }
    }
}

/// A DNS Response.
#[derive(Debug, Serialize)]
pub struct DnsResponse {
    pub response_code: ResponseCode,
    pub authoritative: bool, // if the DNS server is authoritative for the queried hostname, appear in answer
    pub recursion_available: bool, // appear in answer
    pub num_answers: u16,
    pub num_additional: u16, // the number of  records in  Additional section in answer
    pub num_nameservers: u16, // the number of  records in  Authority section in answer
    pub answers: Vec<DnsRecord>,
    pub nameservers: Vec<DnsRecord>,
    pub additionals: Vec<DnsRecord>,
}

impl DnsResponse {
    pub(super) fn parse_response(pkt: &Packet) -> Self {
        let mut answers = Vec::new();
        for answer in &pkt.answers {
            log::debug!("  answer: {}/{:?}", answer.name, answer.data);
            let data = Data::new(&answer.data);
            answers.push(DnsRecord {
                name: answer.name.to_string(),
                data,
                ttl: answer.ttl,
            });
        }
        let mut nameservers = Vec::new();
        for nameserver in &pkt.nameservers {
            let data = Data::new(&nameserver.data);
            nameservers.push(DnsRecord {
                name: nameserver.name.to_string(),
                data,
                ttl: nameserver.ttl,
            });
        }
        let mut additionals = Vec::new();
        for additional in &pkt.additional {
            let data = Data::new(&additional.data);
            additionals.push(DnsRecord {
                name: additional.name.to_string(),
                data,
                ttl: additional.ttl,
            });
        }
        DnsResponse {
            response_code: pkt.header.response_code,
            authoritative: pkt.header.authoritative,
            recursion_available: pkt.header.recursion_available,
            num_answers: pkt.header.answers,
            num_additional: pkt.header.additional,
            num_nameservers: pkt.header.nameservers,
            answers,
            nameservers,
            additionals,
        }
    }
}

/// A DNS Record.
#[derive(Debug, Serialize)]
pub struct DnsRecord {
    pub name: String,
    pub data: Data,
    pub ttl: u32,
}

/// RData types.
#[derive(Debug, Clone, Serialize)]
pub enum Data {
    A(A),
    Aaaa(Aaaa),
    Cname(String),
    Mx(Mx),
    Ns(String),
    Ptr(String),
    Soa(Soa),
    Srv(Srv),
    Txt(String),
    Unknown,
}

impl Data {
    fn new(data: &RData) -> Self {
        match data {
            RData::A(a) => Data::A(*a),
            RData::AAAA(a) => Data::Aaaa(*a),
            RData::CNAME(a) => Data::Cname(a.0.to_string()),
            RData::MX(a) => Data::Mx(Mx {
                preference: a.preference,
                exchange: a.exchange.to_string(),
            }),
            RData::NS(a) => Data::Ns(a.0.to_string()),
            RData::PTR(a) => Data::Ptr(a.0.to_string()),
            RData::SOA(a) => Data::Soa(Soa {
                primary_ns: a.primary_ns.to_string(),
                mailbox: a.mailbox.to_string(),
                serial: a.serial,
                refresh: a.refresh,
                retry: a.retry,
                expire: a.expire,
                minimum_ttl: a.minimum_ttl,
            }),
            RData::SRV(a) => Data::Srv(Srv {
                priority: a.priority,
                weight: a.weight,
                port: a.port,
                target: a.target.to_string(),
            }),
            RData::TXT(a) => Data::Txt(String::from_utf8_lossy(a.bytes).to_string()),
            RData::Unknown(..) => Data::Unknown,
        }
    }
}

/// A DNS mail exchange (MX) record.
#[derive(Debug, PartialEq, Eq, Clone, Serialize)]
pub struct Mx {
    pub preference: u16,
    pub exchange: String,
}

/// A DNS start of authority (SOA) record.
#[derive(Debug, PartialEq, Eq, Clone, Serialize)]
pub struct Soa {
    pub primary_ns: String,
    pub mailbox: String,
    pub serial: u32,
    pub refresh: u32,
    pub retry: u32,
    pub expire: u32,
    pub minimum_ttl: u32,
}

/// A DNS service (SRV) record.
#[derive(Debug, PartialEq, Eq, Clone, Serialize)]
pub struct Srv {
    pub priority: u16,
    pub weight: u16,
    pub port: u16,
    pub target: String,
}
