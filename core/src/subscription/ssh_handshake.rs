//! SSH handshakes.

use crate::conntrack::tcptrack::tcp_context;
use crate::protocols::stream::ssh::parser::*; // TODO remove dependency on ssh_parser
use crate::protocols::stream::ssh::Ssh;
use crate::subscription::*;

pub type KeyExchange = SshKeyExchange;
pub type DhReply = SshDhReply;

pub struct SshHandshake {
    pub five_tuple: FiveTuple,
    pub client_proto: Vec<u8>,
    pub client_software: Vec<u8>,
    pub server_proto: Vec<u8>,
    pub server_software: Vec<u8>,
    pub client_ssh_alg: KeyExchange,
    pub server_ssh_alg: KeyExchange,
    pub client_dh_key_e: Vec<u8>,
    pub server_dh_reply: DhReply,
}

impl SshHandshake {
    // public methods
}

impl Subscribable for SshHandshake {
    type Interm = IntermSsh;

    fn needs_reassembly() -> bool {
        true
    }

    fn applayer_parser() -> Option<Parser> {
        Some(Parser::Ssh(Box::new(Ssh::default())))
    }

    fn process_packet(
        mbuf: Mbuf,
        subscription: &Subscription<Self>,
        stream_table: &mut ConnTracker<Self::Interm>,
    ) {
        match subscription.packet_filter(&mbuf) {
            PacketFilterResult::MatchTerminal(idx) | PacketFilterResult::MatchNonTerminal(idx) => {
                // log::debug!("MATCH {:?}", idx);
                // check info - tryparse as TCP, if not then drop
                if let Ok(ctxt) = tcp_context(&mbuf, idx) {
                    stream_table.tcp_process(mbuf, ctxt, subscription);
                } else {
                    drop(mbuf);
                }
            }
            _ => {
                // log::debug!("NO MATCH!");
                drop(mbuf);
            }
        }
    }
}

pub struct IntermSsh {
    pub(crate) five_tuple: FiveTuple,
}

impl Reassembled for IntermSsh {
    type Output = SshHandshake;

    fn new(five_tuple: FiveTuple) -> Self {
        IntermSsh { five_tuple }
    }

    fn update_prefilter(
        &mut self,
        _payload: Payload,
        state: ConnState,
        _parser: &mut Parser,
    ) -> ConnState {
        state
    }

    fn update_postfilter(
        &mut self,
        _payload: Payload,
        state: ConnState,
        _subscription: &Subscription<Self::Output>,
    ) -> ConnState {
        state
    }

    fn on_filter_match(
        &mut self,
        _terminate: bool,
        parser: &mut Parser,
        subscription: &Subscription<Self::Output>,
    ) -> ConnState {
        if let Parser::Ssh(ssh) = parser {
            // Only one session per SSH connection
            let parser = ssh.parser.pop_back().unwrap();
            let ssh_handshake = SshHandshake {
                five_tuple: self.five_tuple,
                client_proto: parser.client_proto,
                client_software: parser.client_software,
                server_proto: parser.server_proto,
                server_software: parser.server_software,
                client_ssh_alg: parser.client_ssh_alg,
                server_ssh_alg: parser.server_ssh_alg,
                client_dh_key_e: parser.client_dh_key_e,
                server_dh_reply: parser.server_dh_reply,
            };
            subscription.invoke(ssh_handshake);
        }
        ConnState::Remove
    }

    fn on_filter_nomatch(&mut self, _parser: &Parser) -> ConnState {
        ConnState::Remove
    }
}
