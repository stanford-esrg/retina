use super::ast::Predicate;
use super::ptree::FilterLayer;
use super::{ActionData, Actions};
use crate::protocols::stream::IMPLEMENTED_PROTOCOLS;

#[derive(Clone, Debug)]
pub enum Level {
    // Deliver per-packet
    Packet,
    // Deliver at termination
    Connection,
    // Deliver when session is parsed
    // \note Not tracked - built from session (zero-copy)
    Session,
}

// Specification for one subscription (filter, CB, one or more datatypes)
#[derive(Debug, Clone)]
pub struct SubscriptionSpec {
    // Datatype(s) invoked in callback
    pub datatypes: Vec<DataType>,
    // Pre-parsed filter, used in filtergen
    pub filter: String,
    // Callback as string, used in codegen
    pub callback: String,
    // When the full subscription is ready to be delivered
    // Because all data must be delivered simultaneously, this is
    // set based on latest delivery stage. Data is buffered until
    // all datatypes are ready to be delivered.
    // For example: a callback requesting "packets" and "connection records"
    // is a connection-level subscription
    pub level: Level,
}

// Describes a single subscribable datatype
#[derive(Clone, Debug)]
pub struct DataType {
    // Indicates when delivery can start, dictates per-stage actions
    pub level: Level,
    // Datatype requires parsing app-level data
    pub needs_parse: bool,
    // Datatype requires invoking `update` method
    pub needs_update: bool,
    // Datatype requires tracking packet data
    pub track_packets: bool,
    // Application-layer protocols required
    pub stream_protos: Vec<&'static str>,
    // As string, used in filtergen
    pub as_str: &'static str,
}

impl DataType {
    pub fn new(
        level: Level,
        needs_parse: bool,
        needs_update: bool,
        track_packets: bool,
        stream_protos: Vec<&'static str>,
        as_str: &'static str,
    ) -> Self {

        // Only known stream protocols are accepted
        if let Some(s) = stream_protos
            .iter()
            .find(|s| !IMPLEMENTED_PROTOCOLS.contains(s))
        {
            panic!(
                "{} is not in implemented protocols; options: {:?}",
                s, IMPLEMENTED_PROTOCOLS
            );
        }

        // Packet-level subscriptions are incompatible with stateful operations
        if matches!(level, Level::Packet) {
            assert!(!needs_parse && !needs_update && !track_packets);
        }

        Self {
            level,
            needs_parse,
            needs_update,
            track_packets,
            stream_protos,
            as_str,
        }
    }

    // For testing only
    #[allow(dead_code)]
    pub(crate) fn new_default_connection() -> Self {
        Self::new(Level::Connection, false, true, false, vec![], "Connection")
    }

    // For testing only
    #[allow(dead_code)]
    pub(crate) fn new_default_session() -> Self {
        Self::new(Level::Session, true, false, false, vec![], "Session")
    }

    // For testing only
    #[allow(dead_code)]
    pub(crate) fn new_default_packet() -> Self {
        Self::new(Level::Packet, false, false, false, vec![], "Packet")
    }

    // Returns whether the current filter layer is the earliest where this datatype,
    // with this filter, can be delivered.
    pub(crate) fn should_deliver(&self, filter_layer: &FilterLayer, pred: &Predicate) -> bool {
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
        }
    }

    pub(crate) fn can_deliver(&self, filter_layer: &FilterLayer, pred: &Predicate) -> bool {
        match self.level {
            Level::Packet => {
                match filter_layer {
                    FilterLayer::PacketContinue => pred.on_packet(),
                    FilterLayer::Protocol => pred.on_proto() || pred.on_packet(),
                    _ => true,
                }
            },
            Level::Connection => {
                matches!(filter_layer, FilterLayer::ConnectionDeliver)
            }
            Level::Session => {
                matches!(filter_layer, FilterLayer::Session | FilterLayer::ConnectionDeliver)
            }
        }
    }

    // Helper
    fn needs_update(&self, actions: &mut MatchingActions) {
        if self.needs_update {
            actions.if_matched.data |= ActionData::ConnDataTrack;
            actions.if_matched.terminal_actions |= ActionData::ConnDataTrack;
            actions.if_matching.data |= ActionData::ConnDataTrack;
        }
    }

    // Helper
    fn track_packets(&self, actions: &mut MatchingActions) {
        if self.track_packets {
            actions.if_matched.data |= ActionData::PacketTrack;
            actions.if_matched.terminal_actions |= ActionData::PacketTrack;
            actions.if_matching.data |= ActionData::PacketTrack;
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
            actions.if_matching.data |= ActionData::PacketTrack;
            // Matched packet-level subscription is delivered in filter
        }

        // Connection- and session-level subscriptions depend on the actions required
        self.needs_update(&mut actions);
        self.track_packets(&mut actions);
        if self.needs_parse {
            actions.if_matched.data |= ActionData::ProtoProbe;
            actions.if_matched.terminal_actions |= ActionData::ProtoProbe;
            // In if_matching case, protocol will be probed anyway due to Protocol Filter being applied.
        }

        // Session-level datatype can be delivered when session is parsed
        if matches!(self.level, Level::Session) {
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
            actions.if_matching.data |= ActionData::PacketTrack;
        }

        // Connection- and session-level subscriptions depend on the actions required
        self.needs_update(&mut actions);
        self.track_packets(&mut actions);

        if matches!(self.level, Level::Session) {
            // Deliver session when parsed (will implicitly parse session)
            actions.if_matched.data |= ActionData::SessionDeliver;
            actions.if_matched.terminal_actions |= ActionData::SessionDeliver;
        } else if self.needs_parse {
            // Connection-level subscription needs parse
            actions.if_matched.data |= ActionData::SessionParse;
            actions.if_matched.terminal_actions |= ActionData::SessionParse;
        }

        // Can deliver session when parsed
        if matches!(self.level, Level::Session) {
            actions.if_matched.data |= ActionData::SessionDeliver;
            actions.if_matched.terminal_actions |= ActionData::SessionDeliver;
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
        self.track_packets(&mut actions);
        if matches!(sub_level, Level::Connection) && matches!(self.level, Level::Session) {
            actions.if_matched.data |= ActionData::SessionTrack;
        }
        // If we parsed a session and it isn't deliverable, it should be tracked
        if self.needs_parse && !matches!(self.level, Level::Session) {
            actions.if_matched.data |= ActionData::SessionTrack;
        }

        // Session-level subscriptions will be delivered in session filter

        MatchingActions {
            if_matched: actions.if_matched,
            if_matching: Actions::new(), // last filter applied
        }
    }
}

// Helper type to track possible actions for a subscription
#[derive(Debug, Clone)]
pub struct MatchingActions {
    // Actions the subscription requires on terminal match
    pub if_matched: Actions,
    // Actions the subscription requires on non-terminal match
    pub if_matching: Actions,
}

impl MatchingActions {
    fn new() -> Self {
        Self {
            if_matched: Actions::new(),
            if_matching: Actions::new(),
        }
    }

    fn push(&mut self, actions: &MatchingActions) {
        self.if_matched.push(&actions.if_matched);
        self.if_matching.push(&actions.if_matching);
    }
}

impl SubscriptionSpec {
    pub fn new(filter: String, callback: String) -> Self {
        Self {
            datatypes: vec![],
            filter: filter,
            callback: callback,
            level: Level::Packet, // Will be overwritten by any future levels
        }
    }

    // Update subscription level when new datatype is added
    // Latest delivery always takes priority
    fn update_level(&mut self, next_level: &Level) {
        if matches!(self.level, Level::Connection) || matches!(next_level, Level::Connection) {
            self.level = Level::Connection;
        } else if matches!(self.level, Level::Session) || matches!(next_level, Level::Session) {
            self.level = Level::Session;
        } else {
            self.level = Level::Packet;
        }
    }

    pub fn add_datatype(&mut self, datatype: DataType) {
        self.update_level(&datatype.level);
        self.datatypes.push(datatype);
    }

    // For testing only
    #[allow(dead_code)]
    pub(crate) fn new_default_connection() -> Self {
        let mut spec = Self::new(String::from("fil"), String::from("cb"));
        spec.level = Level::Connection;
        spec.datatypes.push(DataType::new_default_connection());
        spec
    }

    // For testing only
    #[allow(dead_code)]
    pub fn new_default_session() -> Self {
        let mut spec = Self::new(String::from("fil"), String::from("cb"));
        spec.level = Level::Session;
        spec.datatypes.push(DataType::new_default_session());
        spec
    }

    // For testing only
    #[allow(dead_code)]
    pub fn new_default_packet() -> Self {
        let mut spec = Self::new(String::from("fil"), String::from("cb"));
        spec.level = Level::Packet;
        spec.datatypes.push(DataType::new_default_packet());
        spec
    }

    // Format subscription as "callback(datatypes)"
    pub fn as_str(&self) -> String {
        let datatype_str: Vec<&'static str> = self.datatypes.iter().map(|d| d.as_str).collect();
        format!("{}({})", self.callback, datatype_str.join(", ")).to_string()
    }

    // Should this datatype be delivered if the filter matched
    pub(crate) fn should_deliver(&self, filter_layer: FilterLayer, pred: &Predicate) -> bool {
        self.datatypes
            .iter()
            .any(|d| d.should_deliver(&filter_layer, pred))
            && self
                .datatypes
                .iter()
                .all(|d| d.can_deliver(&filter_layer, pred))
    }

    // Actions for filter applied for each packet
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

    // Actions for first packet in connection
    pub(crate) fn packet_filter(&self) -> MatchingActions {
        let mut actions = MatchingActions::new();
        for datatype in &self.datatypes {
            actions.push(&datatype.packet_filter(&self.level));
        }
        actions.if_matching.data |= ActionData::ProtoFilter;
        actions
    }

    // Actions for when app-layer protocol identified
    pub(crate) fn proto_filter(&self) -> MatchingActions {
        let mut actions = MatchingActions::new();
        for datatype in &self.datatypes {
            actions.push(&datatype.proto_filter(&self.level));
        }
        actions.if_matching.data |= ActionData::SessionFilter;
        actions
    }

    // Actions for when session fully parsed
    pub(crate) fn session_filter(&self) -> MatchingActions {
        let mut actions = MatchingActions::new();
        for datatype in &self.datatypes {
            actions.push(&datatype.session_filter(&self.level));
        }
        actions
    }

    // Returns the actions that the subscription requires for a given filter layer
    // if the filter has fully (terminally) matched
    pub(crate) fn with_term_filter(&self, filter_layer: FilterLayer,
                                    pred: &Predicate) -> Actions {
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
            },
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
            FilterLayer::PacketContinue => {
                self.packet_continue().if_matching
            }
            FilterLayer::Packet => {
                self.packet_filter().if_matching
            }
            FilterLayer::Protocol => {
                self.proto_filter().if_matching
            }
            FilterLayer::Session => {
                self.session_filter().if_matching
            }
            FilterLayer::ConnectionDeliver | FilterLayer::PacketDeliver => {
                Actions::new()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_multispec() {
        let datatype_session = DataType::new_default_session();
        let datatype_connection = DataType::new_default_connection();
        let mut spec = SubscriptionSpec::new(String::from(""), String::from("cb"));
        spec.add_datatype(datatype_session);
        assert!(matches!(spec.level, Level::Session));
        spec.add_datatype(datatype_connection);
        assert!(matches!(spec.level, Level::Connection));

        let matching_actions = spec.packet_filter();
        assert!(matching_actions.if_matching.parse_any());
        assert!(matching_actions.if_matching.track_pdu());

        let matching_actions = spec.proto_filter();
        assert!(matching_actions.if_matching.parse_any());
        assert!(matching_actions.if_matching.track_pdu());

        let mut spec = SubscriptionSpec::new(String::from(""), String::from("cb"));
        spec.add_datatype(DataType::new_default_packet());
        assert!(spec.proto_filter().if_matched.packet_deliver());
        assert!(spec.proto_filter().if_matching.buffer_frame());
    }
}
