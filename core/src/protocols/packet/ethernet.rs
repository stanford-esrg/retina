//! Ethernet packet.

use crate::memory::mbuf::Mbuf;
use crate::protocols::packet::{Packet, PacketHeader, PacketParseError};
use crate::utils::types::*;

use anyhow::{bail, Result};
use pnet::datalink::MacAddr;

const VLAN_802_1Q: u16 = 0x8100;
const VLAN_802_1AD: u16 = 0x88a8;

const TAG_SIZE: usize = 4;
const HDR_SIZE: usize = 14;
const HDR_SIZE_802_1Q: usize = HDR_SIZE + TAG_SIZE;
const HDR_SIZE_802_1AD: usize = HDR_SIZE_802_1Q + TAG_SIZE;

/// An Ethernet frame.
///
/// On networks that support virtual LANs, the frame may include a VLAN tag after the source MAC
/// address. Double-tagged frames (QinQ) are not yet supported.
#[derive(Debug)]
pub struct Ethernet<'a> {
    /// Fixed header.
    header: EthernetHeader,
    /// Offset to `header` from the start of `mbuf`.
    offset: usize,
    /// Packet buffer.
    mbuf: &'a Mbuf,
}

impl<'a> Ethernet<'a> {
    /// Returns the destination MAC address.
    #[inline]
    pub fn dst(&self) -> MacAddr {
        self.header.dst
    }

    /// Returns the source MAC address.
    #[inline]
    pub fn src(&self) -> MacAddr {
        self.header.src
    }

    /// Returns the encapsulated protocol identifier for untagged and single-tagged frames, and `0`
    /// for incorrectly fornatted and (not yet supported) double-tagged frames,.
    #[inline]
    pub fn ether_type(&self) -> u16 {
        self.next_header().unwrap_or(0) as u16
    }
}

impl<'a> Packet<'a> for Ethernet<'a> {
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
        let ether_type: u16 = u16::from(self.header.ether_type);
        match ether_type {
            VLAN_802_1Q => {
                if let Ok(dot1q) = self.mbuf.get_data(HDR_SIZE) {
                    let dot1q: Dot1q = unsafe { *dot1q };
                    Some(u16::from(dot1q.ether_type).into())
                } else {
                    None
                }
            }
            VLAN_802_1AD => {
                // Unimplemented. TODO: support QinQ
                None
            }
            _ => Some(ether_type.into()),
        }
    }

    fn parse_from(outer: &'a impl Packet<'a>) -> Result<Self>
    where
        Self: Sized,
    {
        if let Ok(header) = outer.mbuf().get_data(0) {
            Ok(Ethernet {
                header: unsafe { *header },
                offset: 0,
                mbuf: outer.mbuf(),
            })
        } else {
            bail!(PacketParseError::InvalidRead)
        }
    }
}

/// Fixed portion of an Ethernet header.
#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
struct EthernetHeader {
    dst: MacAddr,
    src: MacAddr,
    ether_type: u16be,
}

impl PacketHeader for EthernetHeader {
    fn length(&self) -> usize {
        match self.ether_type.into() {
            VLAN_802_1Q => HDR_SIZE_802_1Q,
            VLAN_802_1AD => HDR_SIZE_802_1AD,
            _ => HDR_SIZE,
        }
    }
}

/// 802.1Q tag control information and next EtherType.
///
/// ## Remarks
/// This is not a 801.1Q header. The first 16 bits of `Dot1q` is the TCI field and the second 16
/// bits is the EtherType of the encapsulated protocol.
#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
struct Dot1q {
    tci: u16be,
    ether_type: u16be,
}

impl PacketHeader for Dot1q {
    /// The four bytes that make up the second byte of the 802.1Q header and the EtherType of the
    /// encapsulated protocol.
    fn length(&self) -> usize {
        TAG_SIZE
    }
}

// TODO: Implement QinQ.
