//! Utilities for defining how a subscribed datatype is tracked and delivered.

use super::ast::Predicate;
use super::ptree::FilterLayer;
use super::{ActionData, Actions};
use serde::{Deserialize, Serialize};

/// The abstraction levels for subscribable datatypes
/// These essentially dictate at what point a datatype can/should be delivered
#[derive(Clone, Debug, Copy)]
pub enum Level {
    /// Deliver per-packet
    /// If needed, packets will be cached by the framework until filter match
    /// Important: packet-level subscriptions are delivered as follows for TCP:
    /// - For filters that can match at the packet layer: pre-reassembly
    /// - For all other filters: post-reassembly
    Packet,
    /// Deliver at (UDP/TCP) connection termination
    Connection,
    /// Deliver when session is parsed
    /// Note: only one session-level datatype is permitted per subscription.
    Session,
    /// Deliver at any point in the connection
    /// Static-only subscriptions are delivered either on first packet
    /// (if possible) or at connection termination (otherwise).
    Static,
    /// Applicable only to subscriptions. Indicates that the associated
    /// callback is one for which data will be delivered in a streaming capacity.
    Streaming(Streaming),
}

impl Level {
    /// Whether a datatype at this Level can be delivered
    /// in a streaming callback.
    pub fn can_stream(&self) -> bool {
        matches!(self, Level::Connection)
    }
}

/// Associated data for streaming callbacks.
#[derive(Clone, Debug, Copy, Serialize, Deserialize)]
pub enum Streaming {
    Seconds(f32),
    Packets(u32),
    Bytes(u32),
    // TODO - PayloadBytes (in packets, L4, L6/L7), PayloadPackets, reassembled...
}

impl From<(&str, f32)> for Streaming {
    fn from(inp: (&str, f32)) -> Self {
        match inp.0.to_lowercase().as_str() {
            "seconds" => Streaming::Seconds(inp.1),
            "packets" => Streaming::Packets(inp.1 as u32),
            "bytes" => Streaming::Bytes(inp.1 as u32),
            _ => panic!("Unknown Streaming variant: {}", inp.0),
        }
    }
}

use proc_macro2::Span;
use quote::{quote, ToTokens};

impl ToTokens for Streaming {
    fn to_tokens(&self, tokens: &mut proc_macro2::TokenStream) {
        tokens.extend(match self {
            Streaming::Seconds(val) => {
                let val = syn::LitFloat::new(&val.to_string(), Span::call_site());
                quote! { Streaming::Seconds(#val as f32) }
            }
            Streaming::Packets(val) => {
                let val = syn::LitInt::new(&val.to_string(), Span::call_site());
                quote! { Streaming::Packets(#val) }
            }
            Streaming::Bytes(val) => {
                let val = syn::LitInt::new(&val.to_string(), Span::call_site());
                quote! { Streaming::Bytes(#val) }
            }
        })
    }
}

/// Specification for one complete subscription
/// A subscription is defined as a filter, callback, and one or more datatypes
/// This is public to be accessible by the filtergen crate.
#[derive(Debug, Clone)]
pub struct SubscriptionSpec {
    /// Datatype(s) invoked in callback
    pub datatypes: Vec<DataType>,
    /// String representation of the filter used in this subscription.
    pub filter: String,
    /// Callback as string.
    /// This is used in code generation and for displaying PTrees.
    pub callback: String,
    /// The Level of the full subscription, indicating the earliest stage
    /// at which, if the filter has matched, all datatypes can be delivered.
    /// If needed, data is buffered until the full subscription can be delivered.
    pub level: Level,
}

/// Describes a single subscribable datatype and the operations it requires
#[derive(Clone, Debug)]
pub struct DataType {
    /// The Level of this DataType
    pub level: Level,
    /// True if  the datatype requires parsing application-level sessions
    pub needs_parse: bool,
    /// True if the datatype requires the framework to buffer matched sessions
    pub track_sessions: bool,
    /// True if the datatype requires invoking `update` method before reassembly
    pub needs_update: bool,
    /// True if the datatype requires reassembly (for `track_packets` or `update`)
    pub needs_reassembly: bool,
    /// True if the datatype requires tracking packets
    pub needs_packet_track: bool,
    /// A vector of the application-layer parsers required by this datatype
    /// Retina loads the union of parsers required by all datatypes and filters
    pub stream_protos: Vec<&'static str>,
    /// The name of the datatype as a string, used in code generation and Display.
    pub as_str: &'static str,
}

impl DataType {
    /// Creates a typical datatype for tracking per-connection statistics.
    /// (Connection-level, no parsing, pre-reassembly updates required)
    pub fn new_default_connection(as_str: &'static str) -> Self {
        Self {
            level: Level::Connection,
            needs_parse: false,
            track_sessions: false,
            needs_update: true,
            needs_reassembly: false,
            needs_packet_track: false,
            stream_protos: vec![],
            as_str,
        }
    }

    /// Creates a typical datatype for parsed application-layer data
    /// (Session-level, parsing required)
    pub fn new_default_session(as_str: &'static str, stream_protos: Vec<&'static str>) -> Self {
        Self {
            level: Level::Session,
            needs_parse: true,
            track_sessions: false,
            needs_update: false,
            needs_reassembly: false,
            needs_packet_track: false,
            stream_protos,
            as_str,
        }
    }

    /// Creates a typical datatype for packet data
    /// (Packet-level, no operations required)
    pub fn new_default_packet(as_str: &'static str) -> Self {
        Self {
            level: Level::Packet,
            needs_parse: false,
            track_sessions: false,
            needs_update: false,
            needs_reassembly: false,
            needs_packet_track: false,
            stream_protos: vec![],
            as_str,
        }
    }

    /// Creates a typical datatype for static data
    /// (Static-level, no operations required)
    pub fn new_default_static(as_str: &'static str) -> Self {
        Self {
            level: Level::Static,
            needs_parse: false,
            track_sessions: false,
            needs_update: false,
            needs_reassembly: false,
            needs_packet_track: false,
            stream_protos: vec![],
            as_str,
        }
    }

    /// Creates a typical datatype for a packet list
    /// (Connection-level, requires updates in order to track packets)
    pub fn new_default_pktlist(as_str: &'static str, needs_reassembly: bool) -> Self {
        DataType {
            level: Level::Connection,
            needs_parse: false,
            track_sessions: false,
            needs_update: false,
            needs_reassembly,
            needs_packet_track: true,
            stream_protos: vec![],
            as_str,
        }
    }

    // Returns whether the current filter layer is the earliest where this datatype,
    // with this filter, can be delivered.
    pub(crate) fn should_deliver(
        &self,
        filter_layer: &FilterLayer,
        pred: &Predicate,
        subscription_level: &Level,
    ) -> bool {
        match self.level {
            Level::Packet => {
                match filter_layer {
                    FilterLayer::PacketContinue => pred.on_packet(),
                    FilterLayer::Protocol => pred.on_proto(),
                    FilterLayer::Session => pred.on_session(),
                    FilterLayer::PacketDeliver => true,
                    FilterLayer::ConnectionDeliver | FilterLayer::Packet => {
                        // Packet: Action-only
                        // Conn. deliver: packets delivered when matched, not at termination
                        false
                    }
                }
            }
            Level::Connection => {
                matches!(filter_layer, FilterLayer::ConnectionDeliver)
            }
            Level::Session => {
                matches!(filter_layer, FilterLayer::Session)
            }
            Level::Static => {
                // Static-only subscription
                if !matches!(subscription_level, Level::Static) {
                    return false;
                }
                match pred.on_packet() {
                    // Deliver on first packet in connection (1x/connection)
                    true => matches!(filter_layer, FilterLayer::Packet),
                    // Deliver on connection termination (1x/connection)
                    false => matches!(filter_layer, FilterLayer::ConnectionDeliver),
                }
                // Since protocol/session filter could be >1x/connection, can't
                // deliver in those filters.
            }
            Level::Streaming(_) => panic!("Datatypes should not be streaming"),
        }
    }

    // Returns whether, at the current filter layer, this datatype with this filter predicate
    // *could* be delivered.
    pub(crate) fn can_deliver(&self, filter_layer: &FilterLayer, pred: &Predicate) -> bool {
        match self.level {
            Level::Packet => match filter_layer {
                FilterLayer::PacketContinue => pred.on_packet(),
                FilterLayer::Protocol => pred.on_proto() || pred.on_packet(),
                _ => true,
            },
            Level::Connection => {
                matches!(filter_layer, FilterLayer::ConnectionDeliver)
            }
            Level::Session => {
                matches!(
                    filter_layer,
                    FilterLayer::Session | FilterLayer::ConnectionDeliver
                )
            }
            Level::Static => true,
            Level::Streaming(_) => panic!("Datatypes should not be streaming"),
        }
    }

    // Helper
    fn needs_update(&self, actions: &mut MatchingActions) {
        if self.needs_update {
            actions.if_matched.data |= ActionData::UpdatePDU;
            actions.if_matched.terminal_actions |= ActionData::UpdatePDU;
            actions.if_matching.data |= ActionData::UpdatePDU;
        }
        if self.needs_reassembly {
            actions.if_matched.data |= ActionData::Reassemble;
            actions.if_matched.terminal_actions |= ActionData::Reassemble;
            actions.if_matching.data |= ActionData::Reassemble;
        }
        if self.needs_packet_track {
            actions.if_matched.data |= ActionData::PacketTrack;
            actions.if_matched.terminal_actions |= ActionData::PacketTrack;
            actions.if_matching.data |= ActionData::PacketTrack;
        }
    }

    // Helper for proto_filter and session_filter
    fn track_sessions(&self, actions: &mut MatchingActions, sub_level: &Level) {
        // SessionTrack should only be terminal if matched at packet layer
        // After parsing is complete, session will be tracked if it matched
        // at any layer. See "on_parse" in conntrack mod.
        if (matches!(sub_level, Level::Connection) || matches!(sub_level, Level::Streaming(_)))
            && (matches!(self.level, Level::Session) || self.needs_parse)
        {
            actions.if_matched.data |= ActionData::SessionTrack;
        }
    }

    fn conn_deliver(&self, sub_level: &Level, actions: &mut MatchingActions) {
        if matches!(sub_level, Level::Connection) {
            actions.if_matched.data |= ActionData::ConnDeliver;
            actions.if_matched.terminal_actions |= ActionData::ConnDeliver;
        }
    }

    // Actions applied for first packet in connection if filter is
    // matching (non-terminal match) or matched (terminal match)
    pub(crate) fn packet_filter(&self, sub_level: &Level) -> MatchingActions {
        let mut actions = MatchingActions::new();

        // All packet-level datatypes are (1) delivered ASAP (per-packet),
        // and (2) tracked until then.
        if matches!(self.level, Level::Packet) {
            assert!(matches!(sub_level, Level::Packet));
            actions.if_matching.data |= ActionData::PacketCache;
            // Matched packet-level subscription is delivered in filter
        }

        self.needs_update(&mut actions);
        self.conn_deliver(sub_level, &mut actions);

        if self.needs_parse {
            // Framework will need to know it is at probing stage
            actions.if_matched.data |= ActionData::ProtoProbe;
            // Framework will need to know that subscription requiring
            // probing/parsing matched at packet stage
            actions.if_matched.terminal_actions |= ActionData::ProtoProbe;
            // Session can be tracked when/if parsed
            if matches!(sub_level, Level::Connection) {
                actions.if_matched.data |= ActionData::SessionTrack;
                actions.if_matched.terminal_actions |= ActionData::SessionTrack;
            }
            // In if_matching case, protocol will be probed
            // due to Protocol Filter being applied.
        }

        // Session-level subscription can be delivered when session is parsed
        if matches!(self.level, Level::Session)
            && matches!(sub_level, Level::Session | Level::Streaming(_))
        {
            actions.if_matched.data |= ActionData::SessionDeliver;
            actions.if_matched.terminal_actions |= ActionData::SessionDeliver;
        }
        actions
    }

    // Actions applied when the protocol is identified if filter is
    // matching (non-terminal match) or matched (terminal match)
    pub(crate) fn proto_filter(&self, sub_level: &Level) -> MatchingActions {
        let mut actions = MatchingActions::new();
        if matches!(self.level, Level::Packet) {
            assert!(matches!(sub_level, Level::Packet));
            // Deliver all packets in connection
            actions.if_matched.data |= ActionData::PacketDeliver;
            actions.if_matched.terminal_actions |= ActionData::PacketDeliver;
            // Track in case of match in next filter
            actions.if_matching.data |= ActionData::PacketCache;
        }

        self.needs_update(&mut actions);
        self.track_sessions(&mut actions, sub_level);
        self.conn_deliver(sub_level, &mut actions);

        if matches!(self.level, Level::Session)
            && matches!(sub_level, Level::Session | Level::Streaming(_))
        {
            // Deliver session when parsed (done in session filter)
            actions.if_matched.data |= ActionData::SessionDeliver;
        }

        actions
    }

    // Actions applied when the session is fully parsed if filter is
    // matching (non-terminal match) or matched (terminal match)
    pub(crate) fn session_filter(&self, sub_level: &Level) -> MatchingActions {
        let mut actions = MatchingActions::new();
        if matches!(self.level, Level::Packet) {
            assert!(matches!(sub_level, Level::Packet));
            // Deliver all packets in connection
            actions.if_matched.data |= ActionData::PacketDeliver;
            actions.if_matched.terminal_actions |= ActionData::PacketDeliver;
        }

        self.needs_update(&mut actions);
        self.track_sessions(&mut actions, sub_level);
        self.conn_deliver(sub_level, &mut actions);

        // Session-level subscriptions will be delivered in session filter

        MatchingActions {
            if_matched: actions.if_matched,
            if_matching: Actions::new(), // last filter applied
        }
    }
}

// Helper type to track possible actions for a subscription
#[derive(Debug, Clone)]
pub(crate) struct MatchingActions {
    // Actions the subscription requires on terminal match
    pub(crate) if_matched: Actions,
    // Actions the subscription requires on non-terminal match
    pub(crate) if_matching: Actions,
}

impl MatchingActions {
    pub(crate) fn new() -> Self {
        Self {
            if_matched: Actions::new(),
            if_matching: Actions::new(),
        }
    }

    pub(crate) fn push(&mut self, actions: &MatchingActions) {
        self.if_matched.push(&actions.if_matched);
        self.if_matching.push(&actions.if_matching);
    }
}

impl SubscriptionSpec {
    // Create a new specification with no datatypes
    pub fn new(filter: String, callback: String) -> Self {
        Self {
            datatypes: vec![],
            filter,
            callback,
            level: Level::Static, // Will be overwritten by any future levels
        }
    }

    // Update subscription level when new datatype is added
    // Latest delivery always takes priority
    fn update_level(&mut self, next_level: &Level) {
        if matches!(self.level, Level::Connection) || matches!(next_level, Level::Connection) {
            self.level = Level::Connection;
        } else if matches!(self.level, Level::Session) || matches!(next_level, Level::Session) {
            self.level = Level::Session;
        } else if matches!(self.level, Level::Packet) || matches!(next_level, Level::Packet) {
            self.level = Level::Packet;
        }
    }

    /// Perform basic checks on the subscription specification
    /// - One packet-level datatype per subscription
    /// - Packet-level datatype only permitted with static datatype
    /// - At most one session-level datatype per subscription
    pub fn validate_spec(&self) {
        if matches!(self.level, Level::Packet) {
            if self.datatypes.len() > 1 {
                assert!(
                    self.datatypes
                        .iter()
                        .filter(|d| matches!(d.level, Level::Packet))
                        .count()
                        == 1,
                    "Must have one packet-level datatype in packet-level subscription: {:?}",
                    self
                );
                assert!(
                    self.datatypes
                        .iter()
                        .filter(|d| matches!(d.level, Level::Static))
                        .count()
                        >= self.datatypes.len() - 1,
                    "Non-static datatype in packet-level subscription: {:?}",
                    self
                );
            }
        } else {
            assert!(
                self.datatypes
                    .iter()
                    .filter(|d| matches!(d.level, Level::Packet))
                    .count()
                    == 0,
                "Packet-level datatype in non-packet subscription: {:?}",
                self
            );
        }

        if matches!(self.level, Level::Streaming(_)) {
            assert!(
                self.datatypes
                    .iter()
                    .filter(|d| d.level.can_stream())
                    .count()
                    == 1,
                "Must have one streamable datatype in streaming subscription: {:?}",
                self
            ) // TODO should be able to have multiple streaming datatypes.
        }

        assert!(
            self.datatypes
                .iter()
                .filter(|d| matches!(d.level, Level::Session))
                .count()
                <= 1,
            "Multiple session-level datatypes in subscription: {:?}",
            self
        );
    }

    // Add a new datatype to the subscription
    pub fn add_datatype(&mut self, datatype: DataType) {
        if !matches!(self.level, Level::Streaming(_) | Level::Connection) {
            self.update_level(&datatype.level);
        }
        self.datatypes.push(datatype);
    }

    // For testing only
    #[allow(dead_code)]
    pub(crate) fn new_default_connection() -> Self {
        let mut spec = Self::new(String::from("fil"), String::from("cb"));
        spec.level = Level::Connection;
        spec.datatypes
            .push(DataType::new_default_connection("Connection"));
        spec
    }

    // For testing only
    #[allow(dead_code)]
    pub(crate) fn new_default_session() -> Self {
        let mut spec = Self::new(String::from("fil"), String::from("cb"));
        spec.level = Level::Session;
        spec.datatypes
            .push(DataType::new_default_session("Session", vec![]));
        spec
    }

    // For testing only
    #[allow(dead_code)]
    pub(crate) fn new_default_packet() -> Self {
        let mut spec = Self::new(String::from("fil"), String::from("cb"));
        spec.level = Level::Packet;
        spec.datatypes.push(DataType::new_default_packet("Packet"));
        spec
    }

    #[allow(dead_code)]
    pub(crate) fn new_default_streaming() -> Self {
        let mut spec = Self::new(String::from("fil"), String::from("cb"));
        spec.level = Level::Streaming(Streaming::Seconds(10.0));
        spec.datatypes
            .push(DataType::new_default_connection("Connection"));
        spec
    }

    // Format subscription as "callback(datatypes)"
    pub fn as_str(&self) -> String {
        let datatype_str: Vec<&'static str> = self.datatypes.iter().map(|d| d.as_str).collect();
        format!("{}({})", self.callback, datatype_str.join(", ")).to_string()
    }

    // Should this subscription be delivered if the filter matched
    // This should return true for the first filter at which all datatypes can be delivered
    pub(crate) fn should_deliver(&self, filter_layer: FilterLayer, pred: &Predicate) -> bool {
        !matches!(self.level, Level::Streaming(_))
            && self
                .datatypes
                .iter()
                .any(|d| d.should_deliver(&filter_layer, pred, &self.level))
            && self
                .datatypes
                .iter()
                .all(|d| d.can_deliver(&filter_layer, pred))
    }

    // Helpers
    pub(crate) fn deliver_on_session(&self) -> bool {
        matches!(self.level, Level::Session)
            || (matches!(self.level, Level::Streaming(_))
                && self
                    .datatypes
                    .iter()
                    .any(|d| matches!(d.level, Level::Session)))
    }

    pub(crate) fn should_stream(&self, filter_layer: FilterLayer, pred: &Predicate) -> bool {
        if !matches!(self.level, Level::Streaming(_)) {
            return false;
        }
        // Eliminate if some datatype isn't ready to be delivered
        if self
            .datatypes
            .iter()
            .any(|d| !d.can_deliver(&filter_layer, pred) && !d.level.can_stream())
        {
            return false;
        }
        // Case 1: streaming datatypes only
        // Deliver as soon as predicates match
        if self
            .datatypes
            .iter()
            .all(|d| d.level.can_stream() || matches!(d.level, Level::Static))
        {
            return !pred.is_prev_layer(filter_layer, self);
        }
        // Case 2: some non-streaming datatype
        // Deliver as soon as it's ready
        self.datatypes
            .iter()
            .any(|d| d.should_deliver(&filter_layer, pred, &self.level))
    }

    // Actions for the PacketContinue filter stage
    pub(crate) fn packet_continue(&self) -> MatchingActions {
        let mut if_matched = Actions::new();
        let mut if_matching = Actions::new();

        match self.level {
            // All datatypes in subscription are Level::Packet
            Level::Packet => {
                // If filter terminally matched, packet delivered in CB
                if_matching.data |= ActionData::PacketContinue;
            }
            _ => {
                // Forward to conn tracker
                if_matched.data |= ActionData::PacketContinue;
                if_matching.data |= ActionData::PacketContinue;
            }
        }
        MatchingActions {
            if_matched,
            if_matching,
        }
    }

    // Actions for PacketFilter stage
    pub(crate) fn packet_filter(&self) -> MatchingActions {
        let mut actions = MatchingActions::new();
        for datatype in &self.datatypes {
            actions.push(&datatype.packet_filter(&self.level));
        }
        actions.if_matching.data |= ActionData::ProtoFilter;
        if matches!(self.level, Level::Streaming(_)) {
            actions.if_matched.data |= ActionData::Stream;
            actions.if_matched.terminal_actions |= ActionData::Stream;
        }
        actions
    }

    // Actions for ProtocolFilter stage
    pub(crate) fn proto_filter(&self) -> MatchingActions {
        let mut actions = MatchingActions::new();
        for datatype in &self.datatypes {
            actions.push(&datatype.proto_filter(&self.level));
        }
        if matches!(self.level, Level::Static) {
            actions.if_matched.data |= ActionData::ConnDeliver;
            actions.if_matched.terminal_actions |= ActionData::ConnDeliver;
        }
        if matches!(self.level, Level::Streaming(_)) {
            actions.if_matched.data |= ActionData::Stream;
            actions.if_matched.terminal_actions |= ActionData::Stream;
        }
        actions.if_matching.data |= ActionData::SessionFilter;
        actions
    }

    // Actions for the SessionFilter stage
    pub(crate) fn session_filter(&self) -> MatchingActions {
        let mut actions = MatchingActions::new();
        for datatype in &self.datatypes {
            actions.push(&datatype.session_filter(&self.level));
        }
        if matches!(self.level, Level::Static) {
            actions.if_matched.data |= ActionData::ConnDeliver;
            actions.if_matched.terminal_actions |= ActionData::ConnDeliver;
        }
        if matches!(self.level, Level::Streaming(_)) {
            actions.if_matched.data |= ActionData::Stream;
            actions.if_matched.terminal_actions |= ActionData::Stream;
        }
        actions
    }

    // Returns the actions that the subscription requires for a given filter layer
    // if the filter has fully (terminally) matched
    pub(crate) fn with_term_filter(&self, filter_layer: FilterLayer, pred: &Predicate) -> Actions {
        match filter_layer {
            FilterLayer::PacketContinue => self.packet_continue().if_matched,
            FilterLayer::Packet => self.packet_filter().if_matched,
            FilterLayer::Protocol => self.proto_filter().if_matched,
            FilterLayer::Session => {
                let mut actions = self.session_filter().if_matched;
                // Cache session to re-apply filter at end
                if matches!(self.level, Level::Connection) && pred.on_session() {
                    actions.data |= ActionData::SessionTrack;
                }
                actions
            }
            FilterLayer::ConnectionDeliver | FilterLayer::PacketDeliver => {
                // No actions
                Actions::new()
            }
        }
    }

    // Returns the actions that the subscription requires for a given filter layer
    // if the filter has partially (non-terminally) matched
    pub(crate) fn with_nonterm_filter(&self, filter_layer: FilterLayer) -> Actions {
        match filter_layer {
            FilterLayer::PacketContinue => self.packet_continue().if_matching,
            FilterLayer::Packet => self.packet_filter().if_matching,
            FilterLayer::Protocol => self.proto_filter().if_matching,
            FilterLayer::Session => self.session_filter().if_matching,
            FilterLayer::ConnectionDeliver | FilterLayer::PacketDeliver => Actions::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_multispec() {
        let datatype_session = DataType::new_default_session("Session", vec![]);
        let datatype_connection = DataType::new_default_connection("Connection");
        let mut spec = SubscriptionSpec::new(String::from(""), String::from("cb"));
        spec.add_datatype(datatype_session);
        assert!(matches!(spec.level, Level::Session));
        spec.add_datatype(datatype_connection);
        assert!(matches!(spec.level, Level::Connection));

        let matching_actions = spec.packet_filter();
        assert!(matching_actions.if_matching.parse_any());
        assert!(matching_actions.if_matching.update_pdu());

        let matching_actions = spec.proto_filter();
        assert!(matching_actions.if_matching.parse_any());
        assert!(matching_actions.if_matching.update_pdu());

        let mut spec = SubscriptionSpec::new(String::from(""), String::from("cb"));
        spec.add_datatype(DataType::new_default_packet("Packet"));
        assert!(spec.proto_filter().if_matched.packet_deliver());
        assert!(spec.proto_filter().if_matching.cache_packet());

        let mut spec = SubscriptionSpec::new_default_streaming();
        spec.add_datatype(DataType::new_default_session("Session", vec![]));
        assert!(matches!(spec.level, Level::Streaming(_)));
        assert!(spec.proto_filter().if_matched.stream_deliver());
    }
}
