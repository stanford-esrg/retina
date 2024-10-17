use crate::protocols::stream::ConnData;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

use super::{ConnDataError, ConnField};
use anyhow::{bail, Result};

/// IPv4 Connection Metadata.
#[derive(Debug)]
pub struct Ipv4CData {
    src_addr: Ipv4Addr,
    dst_addr: Ipv4Addr,
}

impl Ipv4CData {
    #[inline]
    pub fn src_addr(&self) -> Ipv4Addr {
        self.src_addr
    }

    #[inline]
    pub fn dst_addr(&self) -> Ipv4Addr {
        self.dst_addr
    }
}

impl ConnField for Ipv4CData {
    fn supported_fields() -> Vec<&'static str> {
        vec!["src_addr", "dst_addr"]
    }

    fn parse_from(conn_data: &ConnData) -> Result<Self> {
        if let SocketAddr::V4(src) = conn_data.five_tuple.orig {
            if let SocketAddr::V4(dst) = conn_data.five_tuple.resp {
                return Ok(Self {
                    src_addr: *src.ip(),
                    dst_addr: *dst.ip(),
                });
            }
        }
        bail!(ConnDataError::InvalidProtocol)
    }
}

/// IPv6 Connection Metadata.
#[derive(Debug)]
pub struct Ipv6CData {
    src_addr: Ipv6Addr,
    dst_addr: Ipv6Addr,
}

impl Ipv6CData {
    #[inline]
    pub fn src_addr(&self) -> Ipv6Addr {
        self.src_addr
    }

    #[inline]
    pub fn dst_addr(&self) -> Ipv6Addr {
        self.dst_addr
    }
}

impl ConnField for Ipv6CData {
    fn supported_fields() -> Vec<&'static str> {
        vec!["src_addr", "dst_addr"]
    }

    fn parse_from(conn_data: &ConnData) -> Result<Self> {
        if let SocketAddr::V6(src) = conn_data.five_tuple.orig {
            if let SocketAddr::V6(dst) = conn_data.five_tuple.resp {
                return Ok(Self {
                    src_addr: *src.ip(),
                    dst_addr: *dst.ip(),
                });
            }
        }
        bail!(ConnDataError::InvalidProtocol)
    }
}
