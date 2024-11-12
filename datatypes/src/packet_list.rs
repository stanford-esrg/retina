//! Vectors of raw packet data.
//! All of these types are Connection-level, meaning they are delivered on
//! connection termination.
//!
//! There are two types of packet lists: those containing Mbufs (`Zc` prefix)
//! and those containing raw bytes (as vectors).
//!
//! For the former: Mbufs are shared across these lists via DPDK reference counting,
//! so requesting lists of packets does not require copying. However, it may
//! introduce additional mempool requirements, as Mbufs must be kept in memory
//! for the duration of the connection. This is often particularly infeasible for
//! UDP connections, which must stay in memory until a timeout is reached.
//! In such cases, users may wish to use the non-`Zc` variants.
//!
//! For TCP connections, the non-`Zc` variants wait to clone data until the
//! first few packets have passed or until the packet data is requested.
//! After the first `PKTS_START_CLONE` packets, it is likely that some traffic has
//! been filtered out by the framework (e.g., TLS handshake has been parsed).
//! This is a middle ground between memory usage and compute performance.
//!
//! For UDP connections, this is not feasible without unacceptable mempool utilization;
//! many UDP connections are short-lived, and UDP connections are not "closed" until
//! a timeout period has passed.

use retina_core::{protocols::packet::tcp::TCP_PROTOCOL, L4Pdu, Mbuf};
use crate::PacketList;

/// Pasic raw packet bytes.
#[derive(Debug)]
pub struct PktData {
    pub data: Vec<u8>,
}

impl PktData {
    pub fn new(mbuf: &Mbuf) -> Self {
        Self {
            data: mbuf.data().to_vec(),
        }
    }
}

/// Number of Mbufs to cache before starting to clone data for
/// TCP connections only. If PKTS_START_CLONE is not reached, the
/// data is converted to Vec<u8> on first access.
const PKTS_START_CLONE: usize = 5;

pub trait PktStream {
    fn in_mbufs_own(&mut self) -> Vec<Mbuf>;
    fn in_mbufs_ref(&mut self) -> &mut Vec<Mbuf>;
    fn out_packets(&mut self) -> &mut Vec<PktData>;

    fn drain_mbufs(&mut self) {
        let mut in_mbufs = self.in_mbufs_own();
        for mbuf in in_mbufs.drain(..) {
            self.out_packets().push(PktData::new(&mbuf));
        }
    }

    fn packets(&mut self) -> &Vec<PktData> {
        if self.in_mbufs_ref().is_empty() {
            return self.out_packets();
        }
        self.drain_mbufs();
        self.out_packets()
    }

    fn push(&mut self, pdu: &L4Pdu) {
        if pdu.ctxt.proto == TCP_PROTOCOL &&
           self.in_mbufs_ref().len() < PKTS_START_CLONE {
            self.in_mbufs_ref().push(Mbuf::new_ref(&pdu.mbuf));
            return;
        } else if !self.in_mbufs_ref().is_empty() {
            self.drain_mbufs();
        }
        self.out_packets().push(PktData::new(pdu.mbuf_ref()));
    }
}

/// For a connection, the bidirectional stream of packets
/// in the order received by the framework.
#[derive(Debug)]
pub struct BidirPktStream {
    /// The raw packet data.
    pub packets: Vec<PktData>,
    /// The first few packets are stored as Mbufs
    /// before data copies begin.
    mbufs: Vec<Mbuf>,
}

impl PktStream for BidirPktStream {
    fn in_mbufs_own(&mut self) -> Vec<Mbuf> {
       std::mem::take(&mut self.mbufs)
    }

    fn in_mbufs_ref(&mut self) -> &mut Vec<Mbuf> {
        &mut self.mbufs
    }

    fn out_packets(&mut self) -> &mut Vec<PktData> {
        &mut self.packets
    }
}

impl PacketList for BidirPktStream {
    fn new(_first_pkt: &L4Pdu) -> Self {
        Self {
            packets: Vec::new(),
            mbufs: Vec::new(),
        }
    }

    fn update(&mut self, pdu: &L4Pdu, reassembled: bool) {
        if !reassembled {
            self.push(pdu);
        }
    }

    fn clear(&mut self) {
        self.packets.clear();
        self.mbufs.clear();
    }

}

/// For a connection, an originator's (unidirectional) stream of packets
/// in the order received by the framework. For TCP streams, the
/// "originator" is the endpoint that sends the first SYN. For UDP,
/// it is the endpoint which sends the first-seen packet.
pub struct OrigPktStream {
    /// The raw packet data.
    pub packets: Vec<PktData>,
    /// The first few packets are stored as Mbufs
    /// before data copies begin.
    mbufs: Vec<Mbuf>,
}

impl PktStream for OrigPktStream {
    fn in_mbufs_own(&mut self) -> Vec<Mbuf> {
        std::mem::take(&mut self.mbufs)
    }

    fn in_mbufs_ref(&mut self) -> &mut Vec<Mbuf> {
        &mut self.mbufs
    }

    fn out_packets(&mut self) -> &mut Vec<PktData> {
        &mut self.packets
    }
}

impl PacketList for OrigPktStream {
    fn new(_first_pkt: &L4Pdu) -> Self {
        Self {
            packets: Vec::new(),
            mbufs: Vec::new(),
        }
    }

    fn update(&mut self, pdu: &L4Pdu, reassembled: bool) {
        if pdu.dir && !reassembled {
            self.push(pdu);
        }
    }

    fn clear(&mut self) {
        self.packets.clear();
        self.mbufs.clear();
    }

}

/// For a connection, a responder's (unidirectional) stream of packets
/// in the order received by the framework. For TCP streams, the
/// "responder" is the endpoint that receives the first SYN and responds
/// with a SYN/ACK. For UDP, it is the endpoint which does not send the
/// first packet.
pub struct RespPktStream {
    /// The raw packet data.
    pub packets: Vec<PktData>,
    /// The first few packets are stored as Mbufs
    /// before data copies begin.
    mbufs: Vec<Mbuf>,
}

impl PktStream for RespPktStream {
    fn in_mbufs_own(&mut self) -> Vec<Mbuf> {
        std::mem::take(&mut self.mbufs)
    }

    fn in_mbufs_ref(&mut self) -> &mut Vec<Mbuf> {
        &mut self.mbufs
    }

    fn out_packets(&mut self) -> &mut Vec<PktData> {
        &mut self.packets
    }
}

impl PacketList for RespPktStream {
    fn new(_first_pkt: &L4Pdu) -> Self {
        Self {
            packets: Vec::new(),
            mbufs: Vec::new(),
        }
    }

    fn update(&mut self, pdu: &L4Pdu, reassembled: bool) {
        if !pdu.dir && !reassembled {
            self.push(pdu);
        }
    }

    fn clear(&mut self) {
        self.packets.clear();
        self.mbufs.clear();
    }

}


/// For a connection, an originator's (unidirectional) stream of packets
/// in reassembled order. This should be used for TCP only.
pub struct OrigPktsReassembled {
    /// The raw packet data.
    pub packets: Vec<PktData>,
    /// The first few packets are stored as Mbufs
    /// before data copies begin.
    mbufs: Vec<Mbuf>,
}

impl PktStream for OrigPktsReassembled {
    fn in_mbufs_own(&mut self) -> Vec<Mbuf> {
        std::mem::take(&mut self.mbufs)
    }

    fn in_mbufs_ref(&mut self) -> &mut Vec<Mbuf> {
        &mut self.mbufs
    }

    fn out_packets(&mut self) -> &mut Vec<PktData> {
        &mut self.packets
    }
}

impl PacketList for OrigPktsReassembled {
    fn new(_first_pkt: &L4Pdu) -> Self {
        Self {
            packets: Vec::new(),
            mbufs: Vec::new(),
        }
    }

    fn update(&mut self, pdu: &L4Pdu, reassembled: bool) {
        if pdu.dir && reassembled {
            self.push(pdu);
        }
    }

    fn clear(&mut self) {
        self.packets.clear();
        self.mbufs.clear();
    }

}


/// For a connection, a responder's (unidirectional) stream of packets
/// in reassembled order. This should be used for TCP only.
pub struct RespPktsReassembled {
    /// The raw packet data.
    pub packets: Vec<PktData>,
    /// The first few packets are stored as Mbufs
    /// before data copies begin.
    mbufs: Vec<Mbuf>,
}

impl PktStream for RespPktsReassembled {
    fn in_mbufs_own(&mut self) -> Vec<Mbuf> {
        std::mem::take(&mut self.mbufs)
    }

    fn in_mbufs_ref(&mut self) -> &mut Vec<Mbuf> {
        &mut self.mbufs
    }

    fn out_packets(&mut self) -> &mut Vec<PktData> {
        &mut self.packets
    }
}

impl PacketList for RespPktsReassembled {
    fn new(_first_pkt: &L4Pdu) -> Self {
        Self {
            packets: Vec::new(),
            mbufs: Vec::new(),
        }
    }

    fn update(&mut self, pdu: &L4Pdu, reassembled: bool) {
        if !pdu.dir && reassembled {
            self.push(pdu);
        }
    }

    fn clear(&mut self) {
        self.packets.clear();
        self.mbufs.clear();
    }

}

/// For a connection, the bidirectional stream of packets
/// in the order received by the framework.
pub struct BidirZcPktStream {
    pub packets: Vec<Mbuf>,
}

impl PacketList for BidirZcPktStream {
    fn new(_first_pkt: &L4Pdu) -> Self {
        Self {
            packets: Vec::new(),
        }
    }

    fn update(&mut self, pdu: &L4Pdu, reassembled: bool) {
        if !reassembled {
            self.packets.push(Mbuf::new_ref(&pdu.mbuf));
        }
    }

    fn clear(&mut self) {
        self.packets.clear();
    }

}

/// For a connection, an originator's (unidirectional) stream of packets
/// in the order received by the framework. For TCP streams, the
/// "originator" is the endpoint that sends the first SYN. For UDP,
/// it is the endpoint which sends the first-seen packet.
pub struct OrigZcPktStream {
    pub packets: Vec<Mbuf>,
}

impl PacketList for OrigZcPktStream {
    fn new(_first_pkt: &L4Pdu) -> Self {
        Self {
            packets: Vec::new(),
        }
    }

    fn update(&mut self, pdu: &L4Pdu, reassembled: bool) {
        if !reassembled && pdu.dir {
            self.packets.push(Mbuf::new_ref(&pdu.mbuf));
        }
    }

    fn clear(&mut self) {
        self.packets.clear();
    }

}

/// For a connection, a responder's (unidirectional) stream of packets
/// in the order received by the framework. For TCP streams, the
/// "responder" is the endpoint that receives the first SYN and responds
/// with a SYN/ACK. For UDP, it is the endpoint which does not send the
/// first packet.
pub struct RespZcPktStream {
    pub packets: Vec<Mbuf>,
}

impl PacketList for RespZcPktStream {
    fn new(_first_pkt: &L4Pdu) -> Self {
        // TODO figure out good default capacity
        Self {
            packets: Vec::new(),
        }
    }

    fn update(&mut self, pdu: &L4Pdu, reassembled: bool) {
        if !reassembled && !pdu.dir {
            self.packets.push(Mbuf::new_ref(&pdu.mbuf));
        }
    }

    fn clear(&mut self) {
        self.packets.clear();
    }

}

/// For a connection, an originator's (unidirectional) stream of packets
/// in reassembled order. This should be used for TCP only.
pub struct OrigZcPktsReassembled {
    pub packets: Vec<Mbuf>,
}

impl PacketList for OrigZcPktsReassembled {
    fn new(_first_pkt: &L4Pdu) -> Self {
        Self {
            packets: Vec::new(),
        }
    }

    fn update(&mut self, pdu: &L4Pdu, reassembled: bool) {
        if reassembled && pdu.dir {
            self.packets.push(Mbuf::new_ref(&pdu.mbuf));
        }
    }

    fn clear(&mut self) {
        self.packets.clear();
    }

}

/// For a connection, a responder's (unidirectional) stream of packets
/// in reassembled order. This should be used for TCP only.
pub struct RespZcPktsReassembled {
    pub packets: Vec<Mbuf>,
}

impl PacketList for RespZcPktsReassembled {
    fn new(_first_pkt: &L4Pdu) -> Self {
        Self {
            packets: Vec::new(),
        }
    }

    fn update(&mut self, pdu: &L4Pdu, reassembled: bool) {
        if reassembled && !pdu.dir {
            self.packets.push(Mbuf::new_ref(&pdu.mbuf));
        }
    }

    fn clear(&mut self) {
        self.packets.clear();
    }

}