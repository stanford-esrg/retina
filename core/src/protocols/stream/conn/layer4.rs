use super::{ConnDataError, ConnField};
use crate::protocols::packet::tcp::TCP_PROTOCOL;
use crate::protocols::packet::udp::UDP_PROTOCOL;
use crate::protocols::stream::ConnData;
use anyhow::{bail, Result};
use std::net::SocketAddr;

/// TCP Connection Metadata.
#[derive(Debug)]
pub struct TcpCData {
    src_port: u16,
    dst_port: u16,
}

impl TcpCData {
    #[inline]
    pub fn src_port(&self) -> u16 {
        self.src_port
    }

    /// Returns the receiving port.
    #[inline]
    pub fn dst_port(&self) -> u16 {
        self.dst_port
    }
}

impl ConnField for TcpCData {
    fn supported_fields() -> Vec<&'static str> {
        vec!["src_port", "dst_port"]
    }

    fn parse_from(conn_data: &ConnData) -> Result<Self> {
        if matches!(conn_data.five_tuple.proto, TCP_PROTOCOL) {
            if let SocketAddr::V4(src) = conn_data.five_tuple.orig {
                if let SocketAddr::V4(dst) = conn_data.five_tuple.resp {
                    return Ok(Self {
                        src_port: src.port(),
                        dst_port: dst.port(),
                    });
                }
            } else if let SocketAddr::V6(src) = conn_data.five_tuple.orig {
                if let SocketAddr::V6(dst) = conn_data.five_tuple.resp {
                    return Ok(Self {
                        src_port: src.port(),
                        dst_port: dst.port(),
                    });
                }
            }
        }
        bail!(ConnDataError::InvalidProtocol)
    }
}
/// UDP Connection Metadata.
#[derive(Debug)]
pub struct UdpCData {
    src_port: u16,
    dst_port: u16,
}

impl UdpCData {
    #[inline]
    pub fn src_port(&self) -> u16 {
        self.src_port
    }

    /// Returns the receiving port.
    #[inline]
    pub fn dst_port(&self) -> u16 {
        self.dst_port
    }
}

impl ConnField for UdpCData {
    fn supported_fields() -> Vec<&'static str> {
        vec!["src_port", "dst_port"]
    }

    fn parse_from(conn_data: &ConnData) -> Result<Self> {
        if matches!(conn_data.five_tuple.proto, UDP_PROTOCOL) {
            if let SocketAddr::V4(src) = conn_data.five_tuple.orig {
                if let SocketAddr::V4(dst) = conn_data.five_tuple.resp {
                    return Ok(Self {
                        src_port: src.port(),
                        dst_port: dst.port(),
                    });
                }
            } else if let SocketAddr::V6(src) = conn_data.five_tuple.orig {
                if let SocketAddr::V6(dst) = conn_data.five_tuple.resp {
                    return Ok(Self {
                        src_port: src.port(),
                        dst_port: dst.port(),
                    });
                }
            }
        }
        bail!(ConnDataError::InvalidProtocol)
    }
}
