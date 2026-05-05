//! UDP packet.

use crate::memory::mbuf::Mbuf;
use crate::protocols::packet::{Packet, PacketHeader, PacketParseError};
use crate::utils::types::*;

use anyhow::{bail, Result};

/// UDP assigned protocol number.
pub const UDP_PROTOCOL: usize = 17;
const UDP_HEADER_LEN: usize = 8;

/// A UDP packet.
#[derive(Debug)]
pub struct Udp<'a> {
    /// Fixed header.
    header: UdpHeader,
    /// Offset to `header` from the start of `mbuf`.
    offset: usize,
    /// Packet buffer.
    mbuf: &'a Mbuf,
}

impl<'a> Udp<'a> {
    /// Returns the sending port.
    #[inline]
    pub fn src_port(&self) -> u16 {
        self.header.src_port.into()
    }

    /// Returns the receiving port.
    #[inline]
    pub fn dst_port(&self) -> u16 {
        self.header.dst_port.into()
    }

    /// Returns the length of packet (both header and payload) in bytes.
    #[inline]
    pub fn length(&self) -> u16 {
        self.header.length.into()
    }

    /// Returns the UDP checksum.
    #[inline]
    pub fn checksum(&self) -> u16 {
        self.header.checksum.into()
    }
}

impl<'a> Packet<'a> for Udp<'a> {
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
        None
    }

    fn parse_from(outer: &'a impl Packet<'a>) -> Result<Self>
    where
        Self: Sized,
    {
        let offset = outer.next_header_offset();
        if let Ok(header) = outer.mbuf().get_data(offset) {
            match outer.next_header() {
                Some(UDP_PROTOCOL) => Ok(Udp {
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

/// UDP header.
#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
struct UdpHeader {
    src_port: u16be,
    dst_port: u16be,
    length: u16be,
    checksum: u16be,
}

impl PacketHeader for UdpHeader {
    /// Header length measured in bytes. Equivalent to the payload offset.
    fn length(&self) -> usize {
        UDP_HEADER_LEN
    }
}
