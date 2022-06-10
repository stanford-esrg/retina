//! Types for parsing and manipulating packet-level network protocols.
//!
//! The structure of this module is adapted from
//! [capsule::packets](https://docs.rs/capsule/0.1.5/capsule/packets/index.html) and
//! [pnet::packet](https://docs.rs/pnet/latest/pnet/packet/index.html). Every packet type represents
//! a single frame on the wire.

pub mod ethernet;
pub mod ipv4;
pub mod ipv6;
pub mod tcp;
pub mod udp;
use crate::memory::mbuf::Mbuf;

use anyhow::Result;
use thiserror::Error;

/// Represents a single packet.
pub trait Packet<'a> {
    /// Reference to the underlying packet buffer.
    fn mbuf(&self) -> &Mbuf;

    /// Offset from the beginning of the header to the start of the payload.
    fn header_len(&self) -> usize;

    /// Offset from the beginning of the packet buffer to the start of the payload.
    fn next_header_offset(&self) -> usize;

    /// Next level IANA protocol number.
    fn next_header(&self) -> Option<usize>;

    /// Parses the `Packet`'s payload as a new `Packet` of type `T`.
    fn parse_to<T: Packet<'a>>(&'a self) -> Result<T>
    where
        Self: Sized,
    {
        T::parse_from(self)
    }

    /// Parses a `Packet` from the outer encapsulating `Packet`'s payload.
    fn parse_from(outer: &'a impl Packet<'a>) -> Result<Self>
    where
        Self: Sized;
}

/// Represents a packet header.
pub trait PacketHeader {
    /// Offset from beginning of the header to start of the payload. It includes the length of any
    /// variable-sized options and tags.
    fn length(&self) -> usize;

    /// Size of the fixed portion of the header in bytes.
    fn size_of() -> usize
    where
        Self: Sized,
    {
        std::mem::size_of::<Self>()
    }
}

#[derive(Error, Debug)]
pub(crate) enum PacketParseError {
    #[error("Invalid protocol")]
    InvalidProtocol,

    #[error("Invalid data read")]
    InvalidRead,
}
