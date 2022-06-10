//! HTTP transaction parsing.
//!
//! ## Remarks
//! Retina currently only parses HTTP 1.x request and response headers, and does not attempt to
//! parse or defragment HTTP bodies that may span multiple packets. This is enough for basic HTTP
//! header analysis, but not for deep inspection of message body contents. Support for
//! request/response continuations, chunked transfer encoding, and body content retrieval, are in
//! progress.
//!
//! This module does support parsing pipelined requests and maintains state for linking requests and
//! responses.
//!
/*
TODO: support request/response continuations (body that spans multiple packets)
TODO: support chunked transfer encoding
TODO: provide request/response body
TODO: HTTP/2 support
*/

pub(crate) mod parser;
mod transaction;

pub use self::transaction::{HttpRequest, HttpResponse};

use serde::Serialize;

/// Parsed HTTP transaction contents.
#[derive(Debug, Serialize)]
pub struct Http {
    /// HTTP Request.
    pub request: HttpRequest,
    /// HTTP Response.
    pub response: HttpResponse,
    /// The pipelined depth into the connection of this transaction.
    pub trans_depth: usize,
}

impl Http {
    /// Returns the request URI, or `""` if it does not exist.
    pub fn uri(&self) -> &str {
        self.request.uri.as_deref().unwrap_or("")
    }

    /// Returns the HTTP method, or `""` if it does not exist.
    pub fn method(&self) -> &str {
        self.request.method.as_deref().unwrap_or("")
    }

    /// Returns the HTTP request version, or `""` if it does not exist.
    pub fn request_version(&self) -> &str {
        self.request.version.as_deref().unwrap_or("")
    }

    /// Returns the user agent string of the user agent, or `""` if it does not exist.
    pub fn user_agent(&self) -> &str {
        self.request.user_agent.as_deref().unwrap_or("")
    }

    /// Returns HTTP cookies sent by the client, or `""` if it does not exist.
    pub fn cookie(&self) -> &str {
        self.request.cookie.as_deref().unwrap_or("")
    }

    /// Returns the domain name of the server specified by the client, or `""` if it does not exist.
    pub fn host(&self) -> &str {
        self.request.host.as_deref().unwrap_or("")
    }

    /// Returns the size of the request body in bytes, or `0` if it does not exist.
    pub fn request_content_length(&self) -> usize {
        self.request.content_length.unwrap_or(0)
    }

    /// Returns the media type of the request resource, or `""` if it does not exist.
    pub fn request_content_type(&self) -> &str {
        self.request.content_type.as_deref().unwrap_or("")
    }

    /// Returns the form of encoding used to transfer the request body, or `""` if it does not
    /// exist.
    pub fn request_transfer_encoding(&self) -> &str {
        self.request.transfer_encoding.as_deref().unwrap_or("")
    }

    /// Returns the HTTP response version, or `""` if it does not exist.
    pub fn response_version(&self) -> &str {
        self.response.version.as_deref().unwrap_or("")
    }

    /// Returns the HTTP status code, or `0` if it does not exist.
    pub fn status_code(&self) -> u16 {
        self.response.status_code.unwrap_or(0)
    }

    /// Returns the HTTP status tet, or `0` if it does not exist.
    pub fn status_msg(&self) -> &str {
        self.response.status_msg.as_deref().unwrap_or("")
    }

    /// Returns the size of the request body in bytes, or `0` if it does not exist.
    pub fn response_content_length(&self) -> usize {
        self.response.content_length.unwrap_or(0)
    }

    /// Returns the media type of the response resource, or `""` if it does not exist.
    pub fn response_content_type(&self) -> &str {
        self.response.content_type.as_deref().unwrap_or("")
    }

    /// Returns the form of encoding used to transfer the response body, or `""` if it does not
    /// exist.
    pub fn response_transfer_encoding(&self) -> &str {
        self.response.transfer_encoding.as_deref().unwrap_or("")
    }

    // TODO: more methods...
}
