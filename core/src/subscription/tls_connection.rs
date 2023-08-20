use crate::conntrack::conn_id::FiveTuple;
use crate::conntrack::pdu::{L4Context, L4Pdu};
use crate::conntrack::ConnTracker;
use crate::filter::FilterResult;
use crate::memory::mbuf::Mbuf;
use crate::protocols::stream::tls::{parser::TlsParser, Tls};
use crate::protocols::stream::{ConnParser, Session, SessionData, ConnData};
use crate::conntrack::conn::conn_info::{ConnState};
use crate::subscription::{Level, Subscribable, Subscription, Trackable, MatchData, Frame};

/// A parsed TLS handshake and connection metadata.
#[derive(Debug)]
pub struct TlsConnection {
    /// Connection 5-tuple.
    pub five_tuple: FiveTuple,
    /// Parsed TLS handshake data.
    pub data: Tls,
    /// Connection frames
    pub connection_frames: Vec<Frame>,
}

impl Subscribable for TlsConnection {
    type Tracked = TrackedTlsConnection;

    fn level() -> Level {
        Level::Connection
    }

    fn parsers() -> Vec<ConnParser> {
        vec![ConnParser::Tls(TlsParser::default())]
    }

    fn process_packet(
        mbuf: Mbuf,
        subscription: &Subscription<Self>,
        conn_tracker: &mut ConnTracker<Self::Tracked>,
    ) {
        match subscription.filter_packet(&mbuf) {
            FilterResult::MatchTerminal(idx) | FilterResult::MatchNonTerminal(idx) => {
                if let Ok(ctxt) = L4Context::new(&mbuf, idx) {
                    conn_tracker.process(mbuf, ctxt, subscription);
                }
            }
            FilterResult::NoMatch => drop(mbuf),
        }
    }
}

#[doc(hidden)]
pub struct TrackedTlsConnection {
    five_tuple: FiveTuple,
    data: Option<Tls>,
    buf: Vec<Frame>,
    match_data: MatchData,
}

impl Trackable for TrackedTlsConnection {
    type Subscribed = TlsConnection;

    fn new(five_tuple: FiveTuple, pkt_term_node: usize) -> Self {
        TrackedTlsConnection { 
            five_tuple, 
            buf: Vec::new(),
            data: None,
            match_data: MatchData::new(pkt_term_node),
        }
    }

    fn deliver_session_on_match(&mut self, session: Session, 
                                _subscription: &Subscription<Self::Subscribed>) -> ConnState {
        if let SessionData::Tls(tls) = session.data {
            if self.data.is_some() {
                panic!("Second TLS handshake in connection: first will be overwritten");
            }
            self.data = Some(*tls);
        }
        ConnState::Tracking
    }

    fn update(&mut self, 
              pdu: L4Pdu, 
              _session_id: Option<usize>,
              _subscription: &Subscription<Self::Subscribed>) {
        self.buf.push(Frame::from_mbuf(&pdu.mbuf_own()));
    }

    fn on_terminate(&mut self, subscription: &Subscription<Self::Subscribed>) {
        if let Some(tls) = std::mem::replace(&mut self.data, None) {
            subscription.invoke(
                TlsConnection {
                    five_tuple: self.five_tuple,
                    data: tls, 
                    connection_frames: std::mem::replace(&mut self.buf, vec![]),
                }
            );
        }
    }

    fn filter_conn(&mut self, conn: &ConnData, subscription:  &Subscription<Self::Subscribed>) -> FilterResult {
        return self.match_data.filter_conn(conn, subscription);
    }
    fn filter_session(&mut self, session: &Session, subscription: &Subscription<Self::Subscribed>) -> bool {
        return self.match_data.filter_session(session, subscription);
    }
}
