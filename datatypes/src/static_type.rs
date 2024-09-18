use super::StaticData;
use retina_core::conntrack::conn_id::FiveTuple;
use retina_core::conntrack::pdu::L4Pdu;

impl StaticData for FiveTuple {
    fn new(first_pkt: &L4Pdu) -> Self {
        FiveTuple::from_ctxt(first_pkt.ctxt)
    }
}

use retina_core::protocols::packet::{ethernet::Ethernet, Packet};

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct EtherTCI(Option<u16>);

impl StaticData for EtherTCI {
    fn new(first_pkt: &L4Pdu) -> Self {
        if let Ok(ethernet) = &Packet::parse_to::<Ethernet>(first_pkt.mbuf_ref()) {
            if let Some(tci) = ethernet.tci() {
                return EtherTCI(Some(tci));
            }
        }
        EtherTCI(None)
    }
}
