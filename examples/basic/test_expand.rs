#![feature(prelude_import)]
#[prelude_import]
use std::prelude::rust_2021::*;
#[macro_use]
extern crate std;
use retina_subscriptiongen::subscription_type;
use retina_core::conntrack::conn_id::FiveTuple;
use retina_core::conntrack::pdu::{L4Context, L4Pdu};
use retina_core::conntrack::ConnTracker;
use retina_core::filter::{FilterResult, FilterResultData};
use retina_core::memory::mbuf::Mbuf;
use retina_core::protocols::stream::tls::{parser::TlsParser, Tls};
use retina_core::protocols::stream::http::{parser::HttpParser, Http};
use retina_core::protocols::stream::{ConnParser, Session, SessionData, ConnData};
use retina_core::conntrack::conn::conn_info::ConnState;
use retina_core::subscription::{Trackable, MatchData, Subscription, Subscribable};
pub enum SubscribableEnum {
    Tls(TlsSubscription),
    Http(HttpSubscription),
}
#[automatically_derived]
impl ::core::fmt::Debug for SubscribableEnum {
    fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
        match self {
            SubscribableEnum::Tls(__self_0) => {
                ::core::fmt::Formatter::debug_tuple_field1_finish(f, "Tls", &__self_0)
            }
            SubscribableEnum::Http(__self_0) => {
                ::core::fmt::Formatter::debug_tuple_field1_finish(f, "Http", &__self_0)
            }
        }
    }
}
pub struct TlsSubscription {
    pub tls: Tls,
    pub five_tuple: FiveTuple,
}
pub struct HttpSubscription {
    pub http: Http,
    pub five_tuple: FiveTuple,
}
pub struct SubscribableWrapper;
impl Subscribable for SubscribableWrapper {
    type Tracked = TrackedWrapper;
    type SubscribedData = SubscribableEnum;
    fn parsers() -> Vec<ConnParser> {
        <[_]>::into_vec(
            #[rustc_box]
            ::alloc::boxed::Box::new([
                ConnParser::Tls(TlsParser::default()),
                ConnParser::Http(HttpParser::default()),
            ]),
        )
    }
    fn process_packet(
        mbuf: Mbuf,
        subscription: &Subscription<Self>,
        conn_tracker: &mut ConnTracker<Self::Tracked>,
    ) {
        let result = subscription.filter_packet(&mbuf);
        if result.terminal_matches != 0 || result.nonterminal_matches != 0 {
            if let Ok(ctxt) = L4Context::new(&mbuf) {
                conn_tracker.process(mbuf, ctxt, subscription, result);
            }
        } else {
            drop(mbuf);
        }
    }
}
pub struct TrackedWrapper {
    match_data: MatchData,
    five_tuple: FiveTuple,
    tls: Option<Tls>,
    http: Vec<Http>,
}
impl Trackable for TrackedWrapper {
    type Subscribed = SubscribableWrapper;
    fn new(five_tuple: FiveTuple, result: FilterResultData) -> Self {
        Self {
            match_data: MatchData::new(result),
            five_tuple: five_tuple,
            tls: None,
            http: Vec::new(),
        }
    }
    fn update(
        &mut self,
        _pdu: L4Pdu,
        _session_id: Option<usize>,
        _subscription: &Subscription<Self::Subscribed>,
    ) {}
    fn on_terminate(&mut self, _subscription: &Subscription<Self::Subscribed>) {}
    fn deliver_session_on_match(
        &mut self,
        session: Session,
        subscription: &Subscription<Self::Subscribed>,
    ) -> ConnState {
        if let SessionData::Tls(tls) = session.data {
            if self.match_data.matched_term_by_idx(0) {
                self.tls = Some(*tls);
            }
        } else if let SessionData::Http(http) = session.data {
            if self.match_data.matched_term_by_idx(1) {
                self.http.push(*http);
            }
        }
        if self.match_data.matched_term_by_idx(0) {
            if let Some(_data) = &self.tls {
                subscription
                    .invoke_idx(
                        SubscribableEnum::Tls(TlsSubscription {
                            tls: std::mem::take(&mut self.tls).unwrap(),
                            five_tuple: self.five_tuple,
                        }),
                        0,
                    );
            }
        }
        if self.match_data.matched_term_by_idx(1) {
            if let Some(data) = self.http.pop() {
                subscription
                    .invoke_idx(
                        SubscribableEnum::Http(HttpSubscription {
                            http: data,
                            five_tuple: self.five_tuple,
                        }),
                        1,
                    );
            }
        }
        ConnState::Remove
    }
    fn filter_packet(&mut self, pkt_filter_result: FilterResultData) {
        self.match_data.filter_packet(pkt_filter_result);
    }
    fn filter_conn(
        &mut self,
        conn: &ConnData,
        subscription: &Subscription<Self::Subscribed>,
    ) -> FilterResult {
        return self.match_data.filter_conn(conn, subscription);
    }
    fn filter_session(
        &mut self,
        session: &Session,
        subscription: &Subscription<Self::Subscribed>,
    ) -> bool {
        return self.match_data.filter_session(session, subscription);
    }
}
fn main() {}
