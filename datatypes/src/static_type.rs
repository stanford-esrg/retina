use super::StaticData;
use retina_core::conntrack::conn_id::FiveTuple;
use retina_core::conntrack::pdu::L4Pdu;

impl StaticData for FiveTuple {
    fn new(first_pkt: &L4Pdu) -> Self {
        FiveTuple::from_ctxt(first_pkt.ctxt)
    }
}
