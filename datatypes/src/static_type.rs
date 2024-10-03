use super::{FromSubscription, StaticData};
use retina_core::conntrack::conn_id::FiveTuple;
use retina_core::conntrack::pdu::L4Pdu;
use retina_core::filter::SubscriptionSpec;

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

use proc_macro2::Span;
use quote::quote;

/// When used as a subscribable datatype, this will be the string literal
/// representing the filter that matched.
///
/// Note that, as usual, if multiple filters are assigned to the same callback,
/// the callback may not be invoked for each matched filter due to filter
/// optimization. Optimization includes early return (mutual exclusion) and
/// parent/child collapse.
/// For example: if `http` and `http.user_agent = x` are both associated with the
/// same callback, then the callback will only be invoked for the `http` filter.
pub type FilterStr<'a> = &'a str;

impl<'a> FromSubscription for FilterStr<'a> {
    fn from_subscription(spec: &SubscriptionSpec) -> proc_macro2::TokenStream {
        let str = syn::LitStr::new(&spec.filter, Span::call_site());
        quote! { &#str }
    }
}

/// A FiveTuple forced to be at the Connection level
pub struct ConnFiveTuple {
    pub five_tuple: FiveTuple,
}

impl StaticData for ConnFiveTuple {
    fn new(first_pkt: &L4Pdu) -> Self {
        Self {
            five_tuple: FiveTuple::from_ctxt(first_pkt.ctxt),
        }
    }
}
