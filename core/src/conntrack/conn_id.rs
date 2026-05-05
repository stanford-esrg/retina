//! Bidirectional connection identifiers.
//!
//! Provides endpoint-specific (distinguishes originator and responder) and generic identifiers for bi-directional connections.

use crate::conntrack::L4Context;

use std::cmp;
use std::fmt;
use std::net::SocketAddr;

use serde::Serialize;

/// Connection 5-tuple.
///
/// The sender of the first observed packet in the connection becomes the originator `orig`, and the
/// recipient becomes the responder `resp`.
#[derive(Debug, Copy, Clone, Hash, Eq, PartialEq, Serialize)]
pub struct FiveTuple {
    /// The originator connection endpoint.
    pub orig: SocketAddr,
    /// The responder connection endpoint.
    pub resp: SocketAddr,
    /// The layer-4 protocol.
    pub proto: usize,
}

impl FiveTuple {
    /// Creates a new 5-tuple from `ctxt`.
    pub(super) fn from_ctxt(ctxt: L4Context) -> Self {
        FiveTuple {
            orig: ctxt.src,
            resp: ctxt.dst,
            proto: ctxt.proto,
        }
    }

    /// Converts a 5-tuple to a non-directional connection identifier.
    pub fn conn_id(&self) -> ConnId {
        ConnId::new(self.orig, self.resp, self.proto)
    }
}

impl fmt::Display for FiveTuple {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} -> ", self.orig)?;
        write!(f, "{}", self.resp)?;
        write!(f, " protocol {}", self.proto)?;
        Ok(())
    }
}

/// A generic connection identifier.
///
/// Identifies a connection independent of the source and destination socket address order. Does not
/// distinguish between the originator and responder of the connection.
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct ConnId(SocketAddr, SocketAddr, usize);

impl ConnId {
    /// Returns the connection ID of a packet with `src` and `dst` IP/port pairs.
    pub(super) fn new(src: SocketAddr, dst: SocketAddr, protocol: usize) -> Self {
        ConnId(cmp::max(src, dst), cmp::min(src, dst), protocol)
    }
}

impl fmt::Display for ConnId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} <> ", self.0)?;
        write!(f, "{}", self.1)?;
        write!(f, " protocol {}", self.2)?;
        Ok(())
    }
}
