use super::StaticData;
use retina_core::conntrack::conn_id::FiveTuple;
use retina_core::conntrack::pdu::L4Pdu;

impl StaticData for FiveTuple {
    fn new(first_pkt: &L4Pdu) -> Self {
        FiveTuple::from_ctxt(first_pkt.ctxt)
    }
}


use retina_core::protocols::packet::{Packet, ethernet::Ethernet};

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct EtherType(Option<u16>);

impl StaticData for EtherType {
    fn new(first_pkt: &L4Pdu) -> Self {
        if let Ok(ethernet) = &Packet::parse_to::<Ethernet>(first_pkt.mbuf_ref()) {
            return EtherType(Some(ethernet.ether_type()));
        }
        EtherType(None)
    }
}