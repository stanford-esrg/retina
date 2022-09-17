use crate::conntrack::conn_id::FiveTuple;
use crate::conntrack::pdu::L4Pdu;
use crate::filter::FilterResult;
use crate::protocols::stream::{
    ConnData, ParseResult, ParserRegistry, ProbeRegistryResult, Session,
};
use crate::subscription::{Level, Subscribable, Subscription, Trackable};

#[derive(Debug)]
pub(crate) struct ConnInfo<T>
where
    T: Trackable,
{
    /// State of Conn
    pub(crate) state: ConnState,
    /// Connection data (for filtering)
    pub(crate) cdata: ConnData,
    /// Subscription data (for delivering)
    pub(crate) sdata: T,
}

impl<T> ConnInfo<T>
where
    T: Trackable,
{
    pub(super) fn new(five_tuple: FiveTuple, pkt_term_node: usize) -> Self {
        ConnInfo {
            state: ConnState::Probing,
            cdata: ConnData::new(five_tuple, pkt_term_node),
            sdata: T::new(five_tuple),
        }
    }

    pub(crate) fn consume_pdu(
        &mut self,
        pdu: L4Pdu,
        subscription: &Subscription<T::Subscribed>,
        registry: &ParserRegistry,
    ) {
        match self.state {
            ConnState::Probing => {
                self.on_probe(pdu, subscription, registry);
            }
            ConnState::Parsing => {
                self.on_parse(pdu, subscription);
            }
            ConnState::Tracking => {
                self.on_track(pdu, subscription);
            }
            ConnState::Remove => {
                drop(pdu);
            }
        }
    }

    fn on_probe(
        &mut self,
        pdu: L4Pdu,
        subscription: &Subscription<T::Subscribed>,
        registry: &ParserRegistry,
    ) {
        match registry.probe_all(&pdu) {
            ProbeRegistryResult::Some(conn_parser) => {
                self.cdata.conn_parser = conn_parser;
                match subscription.filter_conn(&self.cdata) {
                    FilterResult::MatchTerminal(idx) | FilterResult::MatchNonTerminal(idx) => {
                        self.state = ConnState::Parsing;
                        self.cdata.conn_term_node = idx;
                        self.on_parse(pdu, subscription);
                    }
                    FilterResult::NoMatch => {
                        self.state = ConnState::Remove;
                    }
                }
            }
            ProbeRegistryResult::None => {
                // conn_parser remains Unknown
                self.sdata.pre_match(pdu, None);
                match subscription.filter_conn(&self.cdata) {
                    FilterResult::MatchTerminal(_idx) => {
                        self.sdata.on_match(Session::default(), subscription);
                        self.state = self.get_match_state(0);
                    }
                    FilterResult::MatchNonTerminal(_idx) => {
                        self.state = ConnState::Remove;
                    }
                    FilterResult::NoMatch => {
                        self.state = ConnState::Remove;
                    }
                }
            }
            ProbeRegistryResult::Unsure => {
                self.sdata.pre_match(pdu, None);
            }
        }
    }

    fn on_parse(&mut self, pdu: L4Pdu, subscription: &Subscription<T::Subscribed>) {
        match self.cdata.conn_parser.parse(&pdu) {
            ParseResult::Done(id) => {
                self.sdata.pre_match(pdu, Some(id));
                if let Some(session) = self.cdata.conn_parser.remove_session(id) {
                    if subscription.filter_session(&session, self.cdata.conn_term_node) {
                        self.sdata.on_match(session, subscription);
                        self.state = self.get_match_state(id);
                    } else {
                        self.state = self.get_nomatch_state(id);
                    }
                } else {
                    log::error!("Done parse but no mru");
                    self.state = ConnState::Remove;
                }
            }
            ParseResult::Continue(id) => {
                self.sdata.pre_match(pdu, Some(id));
            }
            ParseResult::Skipped => {
                self.sdata.pre_match(pdu, None);
            }
        }
    }

    fn on_track(&mut self, pdu: L4Pdu, subscription: &Subscription<T::Subscribed>) {
        self.sdata.post_match(pdu, subscription);
    }

    fn get_match_state(&self, session_id: usize) -> ConnState {
        if session_id == 0 && T::Subscribed::level() == Level::Connection {
            ConnState::Tracking
        } else {
            self.cdata.conn_parser.session_match_state()
        }
    }

    fn get_nomatch_state(&self, session_id: usize) -> ConnState {
        if session_id == 0 && T::Subscribed::level() == Level::Connection {
            ConnState::Remove
        } else {
            self.cdata.conn_parser.session_nomatch_state()
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum ConnState {
    /// Unknown application-layer protocol, needs probing.
    Probing,
    /// Known application-layer protocol, needs parsing.
    Parsing,
    /// No need to probe or parse, just track. Application-layer protocol may or may not be known.
    Tracking,
    /// Connection will be removed
    Remove,
}
