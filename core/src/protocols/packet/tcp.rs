//! TCP packet.

use crate::memory::mbuf::Mbuf;
use crate::protocols::packet::{Packet, PacketHeader, PacketParseError};
use crate::utils::types::*;

use anyhow::{bail, Result};

/// TCP assigned protocol number.
pub const TCP_PROTOCOL: usize = 6;

// TCP flags.
pub(crate) const CWR: u8 = 0b1000_0000;
pub(crate) const ECE: u8 = 0b0100_0000;
pub(crate) const URG: u8 = 0b0010_0000;
pub(crate) const ACK: u8 = 0b0001_0000;
pub(crate) const PSH: u8 = 0b0000_1000;
pub(crate) const RST: u8 = 0b0000_0100;
pub(crate) const SYN: u8 = 0b0000_0010;
pub(crate) const FIN: u8 = 0b0000_0001;

/// A TCP packet.
///
/// TCP options are not parsed by default.
#[derive(Debug)]
pub struct Tcp<'a> {
    /// Fixed header.
    header: TcpHeader,
    /// Offset to `header` from the start of `mbuf`.
    offset: usize,
    /// Packet buffer.
    mbuf: &'a Mbuf,
}

impl<'a> Tcp<'a> {
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

    /// Returns the sequence number.
    #[inline]
    pub fn seq_no(&self) -> u32 {
        self.header.seq_no.into()
    }

    /// Returns the acknowledgment number.
    #[inline]
    pub fn ack_no(&self) -> u32 {
        self.header.ack_no.into()
    }

    /// Returns the header length measured in 32-bit words.
    #[inline]
    pub fn data_offset(&self) -> u8 {
        (self.header.data_offset_to_ns & 0xf0) >> 4
    }

    /// Returns the reserved bits.
    #[inline]
    pub fn reserved(&self) -> u8 {
        self.header.data_offset_to_ns & 0x0f
    }

    /// Returns the 8-bit field containing the data offset, 3 reserved bits, and the nonce sum bit.
    #[inline]
    pub fn data_offset_to_ns(&self) -> u8 {
        self.header.data_offset_to_ns
    }

    /// Returns the 8-bit TCP flags.
    #[inline]
    pub fn flags(&self) -> u8 {
        self.header.flags
    }

    /// Returns the size of the receive window in window size units.
    #[inline]
    pub fn window(&self) -> u16 {
        self.header.window.into()
    }

    /// Returns the 16-bit checksum field.
    #[inline]
    pub fn checksum(&self) -> u16 {
        self.header.checksum.into()
    }

    /// Returns the urgent pointer.
    #[inline]
    pub fn urgent_pointer(&self) -> u16 {
        self.header.urgent_pointer.into()
    }

    // ------------------------------------------------

    /// Returns `true` if the (historical) nonce sum flag is set.
    #[inline]
    pub fn ns(&self) -> bool {
        (self.header.data_offset_to_ns & 0x01) != 0
    }

    /// Returns `true` if the congestion window reduced flag is set.
    #[inline]
    pub fn cwr(&self) -> bool {
        (self.flags() & CWR) != 0
    }

    /// Returns `true` if the ECN-Echo flag is set.
    #[inline]
    pub fn ece(&self) -> bool {
        (self.flags() & ECE) != 0
    }

    /// Returns `true` if the urgent pointer flag is set.
    #[inline]
    pub fn urg(&self) -> bool {
        (self.flags() & URG) != 0
    }

    /// Returns `true` if the acknowledgment flag is set.
    #[inline]
    pub fn ack(&self) -> bool {
        (self.flags() & ACK) != 0
    }

    /// Returns `true` if the push flag is set.
    #[inline]
    pub fn psh(&self) -> bool {
        (self.flags() & PSH) != 0
    }

    /// Returns `true` if the reset flag is set.
    #[inline]
    pub fn rst(&self) -> bool {
        (self.flags() & RST) != 0
    }

    /// Returns `true` if the synchronize flag is set.
    #[inline]
    pub fn syn(&self) -> bool {
        (self.flags() & SYN) != 0
    }

    /// Returns `true` if the FIN flag is set.
    #[inline]
    pub fn fin(&self) -> bool {
        (self.flags() & FIN) != 0
    }

    /// Returns `true` if both `SYN` and `ACK` flags are set.
    #[inline]
    pub fn synack(&self) -> bool {
        (self.flags() & (ACK | SYN)) != 0
    }
}

impl<'a> Packet<'a> for Tcp<'a> {
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
                Some(TCP_PROTOCOL) => Ok(Tcp {
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

/// Fixed portion of a TCP header.
#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
struct TcpHeader {
    src_port: u16be,
    dst_port: u16be,
    seq_no: u32be,
    ack_no: u32be,
    data_offset_to_ns: u8,
    flags: u8,
    window: u16be,
    checksum: u16be,
    urgent_pointer: u16be,
}

impl PacketHeader for TcpHeader {
    /// Header length measured in bytes. Equivalent to the payload offset.
    ///
    /// This differs from the value of the `Data Offset` field, which measures header length in
    /// 32-bit words.
    fn length(&self) -> usize {
        ((self.data_offset_to_ns & 0xf0) >> 2).into()
    }
}
