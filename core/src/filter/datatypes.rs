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

// Specification for one subscription (filter, CB, datatypes)
#[derive(Debug, Clone)]
pub struct SubscriptionSpec {
    // Datatype(s) invoked in callback
    pub datatypes: Vec<DataType>,
    // Pre-parsed filter, used in filtergen
    pub filter: String,
    // Callback as string, used in codegen
    pub callback: String,
    // Level of the full subscription (latest delivery of datatypes)
    pub level: Level,
}

#[derive(Clone, Debug)]
pub struct DataType {
    // Indicates when delivery can start, dictates per-stage actions
    pub level: Level,
    // Datatype requires parsing app-level data
    pub needs_parse: bool,
    // Datatype requires invoking `update` method
    pub needs_update: bool,
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
        stream_protos: Vec<&'static str>,
        as_str: &'static str
    ) -> Self {
        if let Some(s) = stream_protos
            .iter()
            .find(|s| !IMPLEMENTED_PROTOCOLS.contains(s))
        {
            panic!(
                "{} is not implemented; options: {:?}",
                s, IMPLEMENTED_PROTOCOLS
            );
        }
        Self {
            level,
            needs_parse,
            needs_update,
            stream_protos,
            as_str
        }
    }

    // For testing only
    #[allow(dead_code)]
    pub(crate) fn new_default_connection() -> Self {
        Self::new(Level::Connection, false, true, vec![], "Connection")
    }

    // For testing only
    #[allow(dead_code)]
    pub(crate) fn new_default_session() -> Self {
        Self::new(Level::Session, true, false, vec![], "Session")
    }

    // For testing only
    #[allow(dead_code)]
    pub(crate) fn new_default_packet() -> Self {
        Self::new(Level::Packet, false, false, vec![], "Packet")
    }

    // Should this datatype be delivered if the filter matched
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

    // First packet in connection
    pub(crate) fn packet_filter(&self, sub_level: &Level) -> SubscriptionAction {
        let mut actions = SubscriptionAction::new();
        // Individual datatype level
        match self.level {
            Level::Packet => {
                actions.if_matching.data |= ActionData::PacketTrack;
                if !matches!(sub_level, Level::Packet) {
                    // Packet-level datatype to be delivered later: track packet
                    actions.if_matched.data |= ActionData::PacketTrack;
                }
            }
            Level::Connection => {
                actions.if_matched.data |= ActionData::ConnDataTrack;
                actions.if_matched.terminal_actions |= ActionData::ConnDataTrack;
                actions.if_matching.data |= ActionData::ConnDataTrack;
            }
            Level::Session => {
                actions.if_matched.data |= ActionData::ProtoProbe | ActionData::SessionDeliver;
                actions.if_matched.terminal_actions |= actions.if_matched.data;
            }
        }
        actions
    }

    pub(crate) fn proto_filter(&self, sub_level: &Level) -> SubscriptionAction {
        let mut actions = SubscriptionAction::new();
        match self.level {
            Level::Packet => {
                actions.if_matching.data |= ActionData::PacketTrack;
                match sub_level {
                    Level::Packet => {
                        actions.if_matched.data |= ActionData::PacketDeliver;
                        actions.if_matched.terminal_actions |= ActionData::PacketDeliver;
                    }
                    Level::Connection => {
                        // Track packets until termination
                        actions.if_matched.data |= ActionData::PacketTrack;
                        actions.if_matched.terminal_actions |= ActionData::PacketTrack;
                    }
                    Level::Session => {
                        // Track packets until session parsed
                        actions.if_matched.data |= ActionData::PacketTrack;
                    }
                }
            }
            Level::Connection => {
                actions.if_matched.data |= ActionData::ConnDataTrack;
                actions.if_matched.terminal_actions |= ActionData::ConnDataTrack;
                actions.if_matching.data |= ActionData::ConnDataTrack;
            }
            Level::Session => {
                actions.if_matched.data |= ActionData::SessionDeliver;
                actions.if_matched.terminal_actions |= ActionData::SessionDeliver;
            }
        }
        actions
    }

    pub(crate) fn session_filter(&self, sub_level: &Level) -> SubscriptionAction {
        let mut if_matched = Actions::new();
        match self.level {
            Level::Packet => {
                match sub_level {
                    Level::Packet => {
                        // Deliver all packets in connection
                        if_matched.data |= ActionData::PacketDeliver;
                        if_matched.terminal_actions |= ActionData::PacketDeliver;
                    }
                    Level::Connection => {
                        if_matched.data |= ActionData::PacketTrack;
                        if_matched.data |= ActionData::PacketTrack;
                    }
                    Level::Session => {
                        // Packets will be drained in session_filter
                    }
                }
            }
            Level::Connection => {
                if_matched.data |= ActionData::ConnDataTrack |
                                   // Re-apply session filter at conn. term
                                   ActionData::SessionTrack;
                if_matched.terminal_actions |= ActionData::ConnDataTrack;
            }
            Level::Session => {
                if matches!(sub_level, Level::Connection) {
                    if_matched.data |= ActionData::SessionTrack;
                }
                // Session-level subscription will be delivered in session filter
            }
        }
        SubscriptionAction {
            if_matched,
            if_matching: Actions::new(), // last filter applied
        }
    }
}

pub struct SubscriptionAction {
    pub if_matched: Actions,
    pub if_matching: Actions,
}

impl SubscriptionAction {
    fn new() -> Self {
        Self {
            if_matched: Actions::new(),
            if_matching: Actions::new(),
        }
    }

    fn update(&mut self, actions: &SubscriptionAction) {
        self.if_matched.update(&actions.if_matched);
        self.if_matching.update(&actions.if_matching);
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

    pub fn update_level(&mut self, next_level: &Level) {
        // Latest delivery takes priority
        if matches!(self.level, Level::Connection) ||
           matches!(next_level, Level::Connection) {
            self.level = Level::Connection;
        }
        if matches!(self.level, Level::Session) ||
           matches!(next_level, Level::Session) {
            self.level = Level::Session;
        }
        self.level = Level::Packet;
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

    pub fn as_str(&self) -> String {
        let datatype_str: Vec<&'static str> = self.datatypes.iter()
                                                            .map(|d| d.as_str )
                                                            .collect();
        format!("{}({})", self.callback, datatype_str.join(" or ")).to_string()
    }

    // Should this datatype be delivered if the filter matched
    pub(crate) fn should_deliver(&self, filter_layer: FilterLayer, pred: &Predicate) -> bool {
        self.datatypes
            .iter()
            .all(|d| d.should_deliver(&filter_layer, pred))
    }

    pub(crate) fn packet_continue(&self) -> SubscriptionAction {
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
        SubscriptionAction {
            if_matched,
            if_matching,
        }
    }

    // First packet in connection
    pub(crate) fn packet_filter(&self) -> SubscriptionAction {
        let mut actions = SubscriptionAction::new();
        for datatype in &self.datatypes {
            actions.update(&datatype.packet_filter(&self.level));
        }
        actions
    }

    pub(crate) fn proto_filter(&self) -> SubscriptionAction {
        let mut actions = SubscriptionAction::new();
        for datatype in &self.datatypes {
            actions.update(&datatype.proto_filter(&self.level));
        }
        actions
    }

    pub(crate) fn session_filter(&self) -> SubscriptionAction {
        let mut actions = SubscriptionAction::new();
        for datatype in &self.datatypes {
            actions.update(&datatype.session_filter(&self.level));
        }
        actions
    }

    pub(crate) fn with_term_filter(&self, filter_layer: FilterLayer) -> Actions {
        match filter_layer {
            FilterLayer::PacketContinue => self.packet_continue().if_matched,
            FilterLayer::Packet => self.packet_filter().if_matched,
            FilterLayer::Protocol => self.proto_filter().if_matched,
            FilterLayer::Session => self.session_filter().if_matched,
            FilterLayer::ConnectionDeliver | FilterLayer::PacketDeliver => {
                // No actions
                Actions::new()
            }
        }
    }

    pub(crate) fn with_nonterm_filter(&self, filter_layer: FilterLayer) -> Actions {
        let mut actions = Actions::new();
        match filter_layer {
            FilterLayer::PacketContinue => {
                // Apply next filter
                actions.data |= ActionData::PacketContinue;
                actions.update(&self.packet_continue().if_matching);
            }
            FilterLayer::Packet => {
                // Apply next filter
                actions.data |= ActionData::ProtoFilter;
                actions.update(&self.packet_filter().if_matching);
            }
            FilterLayer::Protocol => {
                // Apply next filter
                actions.data |= ActionData::SessionFilter;
                actions.update(&self.proto_filter().if_matching);
            }
            FilterLayer::Session => {
                actions.update(&self.session_filter().if_matching);
            }
            FilterLayer::ConnectionDeliver | FilterLayer::PacketDeliver => {}
        }
        actions
    }
}
