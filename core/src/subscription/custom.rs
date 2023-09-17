
use crate::conntrack::conn_id::FiveTuple;
use crate::conntrack::pdu::{L4Context, L4Pdu};
use crate::conntrack::ConnTracker;
use crate::filter::{FilterResult, FilterResultData};
use crate::memory::mbuf::Mbuf;
use crate::protocols::stream::tls::{parser::TlsParser, Tls};
use crate::protocols::stream::http::{parser::HttpParser, Http};
use crate::protocols::stream::{ConnParser, Session, SessionData, ConnData};
use crate::conntrack::conn::conn_info::ConnState;
use crate::subscription::{Trackable, MatchData, Subscription, Subscribable};

/*
 * #[subscribable_type]
 * pub enum SubscribableEnum {
 * }
 */

#[derive(Debug)]
pub enum SubscribableEnum {
    Tls(TlsSubscription),
    Http(HttpSubscription),
}
#[derive(Debug)]
pub struct TlsSubscription {
    pub tls: Tls,
    pub five_tuple: FiveTuple,
}

#[derive(Debug)]
pub struct HttpSubscription {
    pub http: Http,
    pub five_tuple: FiveTuple,
}
pub struct SubscribableWrapper;
impl Subscribable for SubscribableWrapper {
    type Tracked = TrackedWrapper;
    type SubscribedData = SubscribableEnum;
    fn parsers() -> Vec<ConnParser> {
        vec![ConnParser::Tls(TlsParser::default()), ConnParser::Http(HttpParser::default()),]
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
            self.tls = Some(*tls);
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
        } else if let SessionData::Http(http) = session.data {
            self.http.push(*http);
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