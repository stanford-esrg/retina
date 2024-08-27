use crate::memory::mbuf::Mbuf;
use crate::protocols::packet::ethernet::Ethernet;
use crate::protocols::packet::ipv4::Ipv4;
use crate::protocols::packet::ipv6::Ipv6;
use crate::protocols::packet::tcp::{Tcp, TCP_PROTOCOL};
use crate::protocols::packet::udp::{Udp, UDP_PROTOCOL};
use crate::protocols::packet::Packet;

use anyhow::{bail, Result};

use std::net::{IpAddr, SocketAddr};

/// Transport-layer protocol data unit for stream reassembly and application-layer protocol parsing.
#[derive(Debug, Clone)]
pub struct L4Pdu {
    /// Internal packet buffer containing frame data.
    pub mbuf: Mbuf,
    /// Transport layer context.
    pub ctxt: L4Context,
    /// `true` if segment is in the direction of orig -> resp.
    pub dir: bool,
}

impl L4Pdu {
    pub(crate) fn new(mbuf: Mbuf, ctxt: L4Context, dir: bool) -> Self {
        L4Pdu { mbuf, ctxt, dir }
    }

    #[inline]
    pub fn mbuf_own(self) -> Mbuf {
        self.mbuf
    }

    #[inline]
    pub fn mbuf_ref(&self) -> &Mbuf {
        &self.mbuf
    }

    #[inline]
    pub fn offset(&self) -> usize {
        self.ctxt.offset
    }

    #[inline]
    pub fn length(&self) -> usize {
        self.ctxt.length
    }

    #[inline]
    pub fn seq_no(&self) -> u32 {
        self.ctxt.seq_no
    }

    #[inline]
    pub fn flags(&self) -> u8 {
        self.ctxt.flags
    }
}

/// Parsed transport-layer context from the packet used for connection tracking.
#[derive(Debug, Clone, Copy)]
pub struct L4Context {
    /// Source socket address.
    pub src: SocketAddr,
    /// Destination socket address.
    pub dst: SocketAddr,
    /// L4 protocol.
    pub proto: usize,
    /// Offset into the mbuf where payload begins.
    pub offset: usize,
    /// Length of the payload in bytes.
    pub length: usize,
    /// Raw sequence number of segment.
    pub seq_no: u32,
    /// TCP flags.
    pub flags: u8,
}

impl L4Context {
    pub fn new(mbuf: &Mbuf) -> Result<Self> {
        if let Ok(eth) = mbuf.parse_to::<Ethernet>() {
            if let Ok(ipv4) = eth.parse_to::<Ipv4>() {
                if let Ok(tcp) = ipv4.parse_to::<Tcp>() {
                    if let Some(payload_size) = (ipv4.total_length() as usize)
                        .checked_sub(ipv4.header_len() + tcp.header_len())
                    {
                        Ok(L4Context {
                            src: SocketAddr::new(IpAddr::V4(ipv4.src_addr()), tcp.src_port()),
                            dst: SocketAddr::new(IpAddr::V4(ipv4.dst_addr()), tcp.dst_port()),
                            proto: TCP_PROTOCOL,
                            offset: tcp.next_header_offset(),
                            length: payload_size,
                            seq_no: tcp.seq_no(),
                            flags: tcp.flags(),
                        })
                    } else {
                        bail!("Malformed Packet");
                    }
                } else if let Ok(udp) = ipv4.parse_to::<Udp>() {
                    if let Some(payload_size) = (ipv4.total_length() as usize)
                        .checked_sub(ipv4.header_len() + udp.header_len())
                    {
                        Ok(L4Context {
                            src: SocketAddr::new(IpAddr::V4(ipv4.src_addr()), udp.src_port()),
                            dst: SocketAddr::new(IpAddr::V4(ipv4.dst_addr()), udp.dst_port()),
                            proto: UDP_PROTOCOL,
                            offset: udp.next_header_offset(),
                            length: payload_size,
                            seq_no: 0,
                            flags: 0,
                        })
                    } else {
                        bail!("Malformed Packet");
                    }
                } else {
                    bail!("Not TCP or UDP");
                }
            } else if let Ok(ipv6) = eth.parse_to::<Ipv6>() {
                if let Ok(tcp) = ipv6.parse_to::<Tcp>() {
                    if let Some(payload_size) =
                        (ipv6.payload_length() as usize).checked_sub(tcp.header_len())
                    {
                        Ok(L4Context {
                            src: SocketAddr::new(IpAddr::V6(ipv6.src_addr()), tcp.src_port()),
                            dst: SocketAddr::new(IpAddr::V6(ipv6.dst_addr()), tcp.dst_port()),
                            proto: TCP_PROTOCOL,
                            offset: tcp.next_header_offset(),
                            length: payload_size,
                            seq_no: tcp.seq_no(),
                            flags: tcp.flags(),
                        })
                    } else {
                        bail!("Malformed Packet");
                    }
                } else if let Ok(udp) = ipv6.parse_to::<Udp>() {
                    if let Some(payload_size) =
                        (ipv6.payload_length() as usize).checked_sub(udp.header_len())
                    {
                        Ok(L4Context {
                            src: SocketAddr::new(IpAddr::V6(ipv6.src_addr()), udp.src_port()),
                            dst: SocketAddr::new(IpAddr::V6(ipv6.dst_addr()), udp.dst_port()),
                            proto: UDP_PROTOCOL,
                            offset: udp.next_header_offset(),
                            length: payload_size,
                            seq_no: 0,
                            flags: 0,
                        })
                    } else {
                        bail!("Malformed Packet");
                    }
                } else {
                    bail!("Not TCP or UDP");
                }
            } else {
                bail!("Not IP");
            }
        } else {
            bail!("Not Ethernet");
        }
    }
}
