//! IPv4 packet.

use crate::memory::mbuf::Mbuf;
use crate::protocols::packet::{Packet, PacketHeader, PacketParseError};
use crate::utils::types::*;

use std::net::Ipv4Addr;

use anyhow::{bail, Result};

/// IPv4 EtherType
const IPV4_PROTOCOL: usize = 0x0800;
/// Flag: "Reserved bit"
const IPV4_RF: u16 = 0x8000;
/// Flag: "Don't fragment"
const IPV4_DF: u16 = 0x4000;
/// Flag: "More fragments"
const IPV4_MF: u16 = 0x2000;
/// Fragment offset part
const IPV4_FRAG_OFFSET: u16 = 0x1FFF;

/// An IPv4 packet.
///
/// IPv4 options are not parsed by default.
#[derive(Debug)]
pub struct Ipv4<'a> {
    /// Fixed header.
    header: Ipv4Header,
    /// Offset to `header` from the start of `mbuf`.
    offset: usize,
    /// Packet buffer.
    mbuf: &'a Mbuf,
}

impl<'a> Ipv4<'a> {
    /// Returns the IP protocol version.
    #[inline]
    pub fn version(&self) -> u8 {
        (self.header.version_ihl & 0xf0) >> 4
    }

    /// Returns the header length measured in 32-bit words (IHL).    
    #[inline]
    pub fn ihl(&self) -> u8 {
        self.header.version_ihl & 0x0f
    }

    /// Returns the 8-bit field containing the version and IHL.   
    #[inline]
    pub fn version_ihl(&self) -> u8 {
        self.header.version_ihl
    }

    /// Returns the differentiated services code point (DSCP).
    #[inline]
    pub fn dscp(&self) -> u8 {
        self.header.dscp_ecn >> 2
    }

    /// Returns the explicit congestion notification (ECN).
    #[inline]
    pub fn ecn(&self) -> u8 {
        self.header.dscp_ecn & 0x03
    }

    /// Returns the differentiated services field.  
    #[inline]
    pub fn dscp_ecn(&self) -> u8 {
        self.header.dscp_ecn
    }

    /// Returns the type of service (former name of the differentiated services field).
    #[inline]
    pub fn type_of_service(&self) -> u8 {
        self.dscp_ecn()
    }

    /// Returns the total length of the packet in bytes, including the header and data.
    #[inline]
    pub fn total_length(&self) -> u16 {
        self.header.total_length.into()
    }

    /// Returns the identification field.
    #[inline]
    pub fn identification(&self) -> u16 {
        self.header.identification.into()
    }

    /// Returns the 16-bit field containing the 3-bit flags and 13-bit fragment offset.
    #[inline]
    pub fn flags_to_fragment_offset(&self) -> u16 {
        self.header.flags_to_fragment_offset.into()
    }

    /// Returns the 3-bit IP flags.
    #[inline]
    pub fn flags(&self) -> u8 {
        (self.flags_to_fragment_offset() >> 13) as u8
    }

    /// Returns `true` if the Reserved flag is set.
    #[inline]
    pub fn rf(&self) -> bool {
        (self.flags_to_fragment_offset() & IPV4_RF) != 0
    }

    /// Returns `true` if the Don't Fragment flag is set.
    #[inline]
    pub fn df(&self) -> bool {
        (self.flags_to_fragment_offset() & IPV4_DF) != 0
    }

    /// Returns `true` if the More Fragments flag is set.
    #[inline]
    pub fn mf(&self) -> bool {
        (self.flags_to_fragment_offset() & IPV4_MF) != 0
    }

    /// Returns the fragment offset in units of 8 bytes.
    #[inline]
    pub fn fragment_offset(&self) -> u16 {
        self.flags_to_fragment_offset() & IPV4_FRAG_OFFSET
    }

    /// Returns the time to live (TTL) of the packet.
    #[inline]
    pub fn time_to_live(&self) -> u8 {
        self.header.time_to_live
    }

    /// Returns the encapsulated protocol identifier.
    #[inline]
    pub fn protocol(&self) -> u8 {
        self.header.protocol
    }

    /// Returns the IPv4 header checksum.
    #[inline]
    pub fn header_checksum(&self) -> u16 {
        self.header.header_checksum.into()
    }

    /// Returns the sender's IPv4 address.
    #[inline]
    pub fn src_addr(&self) -> Ipv4Addr {
        self.header.src_addr
    }

    /// Returns the receiver's IPv4 address.
    #[inline]
    pub fn dst_addr(&self) -> Ipv4Addr {
        self.header.dst_addr
    }
}

impl<'a> Packet<'a> for Ipv4<'a> {
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
        Some(self.protocol().into())
    }

    fn parse_from(outer: &'a impl Packet<'a>) -> Result<Self>
    where
        Self: Sized,
    {
        let offset = outer.next_header_offset();
        if let Ok(header) = outer.mbuf().get_data(offset) {
            match outer.next_header() {
                Some(IPV4_PROTOCOL) => Ok(Ipv4 {
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

/// Fixed portion of an IPv4 header.
#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
struct Ipv4Header {
    version_ihl: u8,
    dscp_ecn: u8,
    total_length: u16be,
    identification: u16be,
    flags_to_fragment_offset: u16be,
    time_to_live: u8,
    protocol: u8,
    header_checksum: u16be,
    src_addr: Ipv4Addr,
    dst_addr: Ipv4Addr,
}

impl PacketHeader for Ipv4Header {
    /// Header length measured in bytes. Equivalent to the payload offset.
    ///
    /// This differs from the value of the `IHL` field, which measures header length in 32-bit
    /// words.
    fn length(&self) -> usize {
        ((self.version_ihl & 0xf) << 2).into()
    }
}
