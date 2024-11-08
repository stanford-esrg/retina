//! Vectors of raw packets.
//! All of these types are Connection-level, meaning they are delivered on
//! connection termination.
//! Note: Mbufs are shared across these lists via DPDK reference counting,
//! so requesting lists of packets does not require copying. However, it may
//! introduce additional mempool requirements, as Mbufs must be kept in memory
//! for the duration of the connection.

use retina_core::{L4Pdu, Mbuf};
use crate::PacketList;

/// For a connection, the bidirectional stream of packets
/// in the order received by the framework.
pub struct PktStream {
    pub packets: Vec<Mbuf>,
}

impl PacketList for PktStream {
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
pub struct OrigPktStream {
    pub packets: Vec<Mbuf>,
}

impl PacketList for OrigPktStream {
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
pub struct RespPktStream {
    pub packets: Vec<Mbuf>,
}

impl PacketList for RespPktStream {
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
pub struct OrigPktsReassembled {
    pub packets: Vec<Mbuf>,
}

impl PacketList for OrigPktsReassembled {
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
pub struct RespPktsReassembled {
    pub packets: Vec<Mbuf>,
}

impl PacketList for RespPktsReassembled {
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