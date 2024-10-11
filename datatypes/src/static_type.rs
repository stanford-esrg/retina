//! Static-level datatypes.
//! A data type is considered "static" if it can be inferred at or before
//! the first packet in a connection and it stays constant throughout a connection.

use super::{FromSubscription, StaticData};
use pnet::datalink::MacAddr;
use retina_core::conntrack::conn_id::FiveTuple;
use retina_core::conntrack::pdu::L4Pdu;
use retina_core::filter::SubscriptionSpec;

/// Subscribable alias for [`retina_core::FiveTuple`]
impl StaticData for FiveTuple {
    fn new(first_pkt: &L4Pdu) -> Self {
        FiveTuple::from_ctxt(first_pkt.ctxt)
    }
}

use retina_core::protocols::packet::{ethernet::Ethernet, Packet};

/// Tag Control Information field on the first packet, or none
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

use proc_macro2::Span;
use quote::quote;

/// The string literal representing a matched filter.
pub type FilterStr<'a> = &'a str;

impl<'a> FromSubscription for FilterStr<'a> {
    fn from_subscription(spec: &SubscriptionSpec) -> proc_macro2::TokenStream {
        let str = syn::LitStr::new(&spec.filter, Span::call_site());
        quote! { &#str }
    }
}

/// The src/dst MAC of a connection
#[derive(Clone, Debug)]
pub struct EthAddr {
    pub src: MacAddr,
    pub dst: MacAddr,
}

impl StaticData for EthAddr {
    fn new(first_pkt: &L4Pdu) -> Self {
        if let Ok(ethernet) = &Packet::parse_to::<Ethernet>(first_pkt.mbuf_ref()) {
            Self {
                src: ethernet.src(),
                dst: ethernet.dst(),
            }
        } else {
            panic!("Non-ethernet packets not supported");
        }
    }
}
