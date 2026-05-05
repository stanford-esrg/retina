//! IPv6 packet.

use crate::memory::mbuf::Mbuf;
use crate::protocols::packet::{Packet, PacketHeader, PacketParseError};
use crate::utils::types::*;

use std::net::Ipv6Addr;

use anyhow::{bail, Result};

const IPV6_PROTOCOL: usize = 0x86DD;
const IPV6_HEADER_LEN: usize = 40;

/// An IPv6 packet.
///
/// Optional IPv6 extension headers are not parsed by default.
#[derive(Debug)]
pub struct Ipv6<'a> {
    /// Fixed header.
    header: Ipv6Header,
    /// Offset to `header` from the start of `mbuf`.
    offset: usize,
    /// Packet buffer.
    mbuf: &'a Mbuf,
}

impl<'a> Ipv6<'a> {
    /// Returns the IP protocol version.
    #[inline]
    pub fn version(&self) -> u8 {
        let v: u32 = (self.header.version_to_flow_label & u32be::from(0xf000_0000)).into();
        (v >> 28) as u8
    }

    /// Returns the differentiated services code point (DSCP).
    #[inline]
    pub fn dscp(&self) -> u8 {
        let v: u32 = (self.header.version_to_flow_label & u32be::from(0x0fc0_0000)).into();
        (v >> 22) as u8
    }

    /// Returns the explicit congestion notification (ECN).
    #[inline]
    pub fn ecn(&self) -> u8 {
        let v: u32 = (self.header.version_to_flow_label & u32be::from(0x0030_0000)).into();
        (v >> 20) as u8
    }

    /// Returns the traffic class (former name of differentiated services field).
    #[inline]
    pub fn traffic_class(&self) -> u8 {
        let v: u32 = (self.header.version_to_flow_label & u32be::from(0x0ff0_0000)).into();
        (v >> 20) as u8
    }

    /// Returns the flow label.
    #[inline]
    pub fn flow_label(&self) -> u32 {
        (self.header.version_to_flow_label & u32be::from(0x000f_ffff)).into()
    }

    /// Returns the 32-bit field containing the version, traffic class, and flow label.
    #[inline]
    pub fn version_to_flow_label(&self) -> u32 {
        self.header.version_to_flow_label.into()
    }

    /// Returns the length of the payload in bytes.
    #[inline]
    pub fn payload_length(&self) -> u16 {
        self.header.payload_length.into()
    }

    /// Returns the encapsulated protocol identifier.
    #[inline]
    pub fn next_header(&self) -> u8 {
        self.header.next_header
    }

    /// Returns hop limit/time to live of the packet.
    #[inline]
    pub fn hop_limit(&self) -> u8 {
        self.header.hop_limit
    }

    /// Returns the sender's IPv6 address.
    #[inline]
    pub fn src_addr(&self) -> Ipv6Addr {
        self.header.src_addr
    }

    /// Returns the receiver's IPv6 address.
    #[inline]
    pub fn dst_addr(&self) -> Ipv6Addr {
        self.header.dst_addr
    }
}

impl<'a> Packet<'a> for Ipv6<'a> {
    fn mbuf(&self) -> &Mbuf {
        self.mbuf
    }

    fn header_len(&self) -> usize {
        self.header.length()
    }

    fn next_header_offset(&self) -> usize {
        self.offset + self.header_len()
    }

    fn next_header(&self) -> Option<usize> {
        Some(self.next_header().into())
    }

    fn parse_from(outer: &'a impl Packet<'a>) -> Result<Self>
    where
        Self: Sized,
    {
        let offset = outer.next_header_offset();
        if let Ok(header) = outer.mbuf().get_data(offset) {
            match outer.next_header() {
                Some(IPV6_PROTOCOL) => Ok(Ipv6 {
                    header: unsafe { *header },
                    offset,
                    mbuf: outer.mbuf(),
                }),
                _ => bail!(PacketParseError::InvalidProtocol),
            }
        } else {
            bail!(PacketParseError::InvalidRead)
        }
    }
}

// Fixed portion of Ipv6 header TODO: handle extension headers
#[derive(Debug, Clone, Copy)]
#[repr(C)]
struct Ipv6Header {
    version_to_flow_label: u32be,
    payload_length: u16be,
    next_header: u8,
    hop_limit: u8,
    src_addr: Ipv6Addr,
    dst_addr: Ipv6Addr,
}

impl PacketHeader for Ipv6Header {
    /// Payload offset
    fn length(&self) -> usize {
        IPV6_HEADER_LEN
    }
}
