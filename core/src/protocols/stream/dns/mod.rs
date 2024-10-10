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

    /// Returns a string representation of the answers
    pub fn answers(&self) -> String {
        if let Some(resp) = &self.response {
            if !resp.answers.is_empty() {
                return serde_json::to_string(&resp.answers).unwrap_or(String::new());
            }
        }
        String::new()
    }

    /// Returns a string representation of the response nameservers
    pub fn nameservers(&self) -> String {
        if let Some(resp) = &self.response {
            if !resp.nameservers.is_empty() {
                return serde_json::to_string(&resp.nameservers).unwrap_or(String::new());
            }
        }
        String::new()
    }

    /// Returns a string representation of the response additionals
    pub fn additionals(&self) -> String {
        if let Some(resp) = &self.response {
            if !resp.additionals.is_empty() {
                return serde_json::to_string(&resp.additionals).unwrap_or(String::new());
            }
        }
        String::new()
    }

    /// Returns a string representation of the response
    pub fn response(&self) -> String {
        if let Some(resp) = &self.response {
            return serde_json::to_string(&resp).unwrap_or(String::new());
        }
        String::new()
    }
}
