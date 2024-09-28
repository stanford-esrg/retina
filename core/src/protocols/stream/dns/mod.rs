//! DNS transaction parsing.

pub mod parser;
mod transaction;

pub use self::transaction::*;

use serde::Serialize;

/// Parsed DNS transaction contents.
///
/// A DNS transaction consists of a query and a response.
#[derive(Clone, Debug, Serialize)]
pub struct Dns {
    /// DNS transaction ID.
    pub transaction_id: u16,
    /// DNS Query.
    pub query: Option<DnsQuery>,
    /// DNS Response.
    pub response: Option<DnsResponse>,
}

impl Dns {
    /// Returns the DNS query domain name, or `""` if no query was observed in the transaction.
    pub fn query_domain(&self) -> &str {
        if let Some(query) = &self.query {
            if !query.queries.is_empty() {
                return &query.queries[0];
            }
        }
        ""
    }
}
