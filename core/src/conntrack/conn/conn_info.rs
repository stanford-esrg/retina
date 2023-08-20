use crate::conntrack::conn_id::FiveTuple;
use crate::conntrack::pdu::L4Pdu;
use crate::filter::FilterResult;
use crate::protocols::stream::{
    ConnData, ParseResult, ParserRegistry, ProbeRegistryResult, Session,
};
use crate::subscription::{Subscription, Trackable};

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
            sdata: T::new(five_tuple, pkt_term_node),
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
                match self.sdata.filter_conn(&self.cdata, subscription) {
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
                self.sdata.update(pdu, None, subscription);
                match self.sdata.filter_conn(&self.cdata, subscription) {
                    FilterResult::MatchTerminal(_idx) => {
                        self.state = self.sdata.deliver_session_on_match(Session::default(), subscription);
                    }
                    FilterResult::MatchNonTerminal(_idx) => {
                        // If no session data, can't apply a session filter.
                        self.state = ConnState::Remove;
                    }
                    FilterResult::NoMatch => {
                        self.state = ConnState::Remove;
                    }
                }
            }
            ProbeRegistryResult::Unsure => {
                self.sdata.update(pdu, None, subscription);
            }
        }
    }

    fn on_parse(&mut self, pdu: L4Pdu, subscription: &Subscription<T::Subscribed>) {
        match self.cdata.conn_parser.parse(&pdu) {
            ParseResult::Done(id) => {
                self.sdata.update(pdu, Some(id), subscription);
                if let Some(session) = self.cdata.conn_parser.remove_session(id) {
                    /* TODOTR CHECK THIS LOGIC */
                    if self.sdata.filter_session(&session, subscription) {
                        // Does the subscription want the connection to stay tracked? 
                        let subscription_state = self.sdata.deliver_session_on_match(session, subscription);
                        // Does the filter want the connection to stay tracked? 
                        let filter_state = self.cdata.conn_parser.session_match_state();
                        if subscription_state == ConnState::Remove && filter_state == ConnState::Remove {
                            self.state = ConnState::Remove;
                        } else if filter_state == ConnState::Parsing {
                            // Example: filtering for `Http` may have multiple sessions per connection
                            // - Regardless of subscribable type, keep tracking sessions
                            self.state = ConnState::Parsing;
                        } else {
                            // Example: filtering for `Tls`, but want the whole connection.
                            // - No need to keep parsing after the handshake, but should still track.
                            self.state = ConnState::Tracking;
                        }
                    } else {
                        /* TODOTR CHECK THIS LOGIC */
                        // May want dependence on subscribable types 
                        // (e.g., force remove if you want to match Connection only on first Session?)
                        self.state = self.cdata.conn_parser.session_nomatch_state();
                    }
                } else {
                    log::error!("Done parse but no mru");
                    self.state = ConnState::Remove;
                }
            }
            ParseResult::Continue(id) => {
                self.sdata.update(pdu, Some(id), subscription);
            }
            ParseResult::Skipped => {
                self.sdata.update(pdu, None, subscription);
            }
        }
    }

    fn on_track(&mut self, pdu: L4Pdu, subscription: &Subscription<T::Subscribed>) {
        self.sdata.update(pdu, None, subscription);
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
