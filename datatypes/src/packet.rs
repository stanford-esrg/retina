//! Raw packet-level datatypes.

use super::FromMbuf;
use retina_core::{conntrack::pdu::L4Context, Mbuf};

/// Subscribable alias for [`retina_core::Mbuf`]
pub type ZcFrame = Mbuf;

impl FromMbuf for ZcFrame {
    fn from_mbuf(mbuf: &Mbuf) -> Option<&Self> {
        Some(mbuf)
    }
}

/// Payload after TCP/UDP headers
pub type Payload = [u8];

impl FromMbuf for Payload {
    fn from_mbuf(mbuf: &Mbuf) -> Option<&Self> {
        if let Ok(ctxt) = L4Context::new(mbuf) {
            let offset = ctxt.offset;
            let payload_len = ctxt.length;
            if let Ok(data) = mbuf.get_data_slice(offset, payload_len) {
                return Some(data);
            }
        }
        None
    }
}
