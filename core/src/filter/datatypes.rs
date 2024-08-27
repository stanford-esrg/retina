use super::ast::Predicate;
use super::{Actions, ActionData};
use super::ptree::FilterLayer;

#[derive(Clone, Debug)]
pub enum Level {
    // Deliver per-packet
    Packet,
    // Deliver at termination
    Connection,
    // Deliver when session is parsed
    Session,
    // [TODO] need to think through
    Streaming,
}

#[derive(Clone, Debug)]
pub struct DataType {
    // Indicates when delivery can start
    pub level: Level, 
    // Datatype requires parsing app-level data
    pub needs_parse: bool,
    // Datatype requires invoking `update` method
    pub needs_update: bool,
    // Extracted from session (zero-copy; not tracked)
    pub from_session: bool,
    // [note] May want other things?
}

// [TODO] allow for more complex datatypes by 
// referring to needs_parse, needs_update
pub struct DataTypeAction {
    pub if_matched: Actions,
    pub if_matching: Actions,
}

impl DataType {
    pub fn new(level: Level, needs_parse: bool, needs_update: bool,
               from_session: bool) -> Self {
        if from_session { 
            assert!(!needs_update);
            assert!(matches!(level, Level::Session));
        }
        Self {
            level,
            needs_parse: needs_parse || from_session,
            needs_update,
            from_session,
        }
    }

    pub fn new_default_connection() -> Self {
        Self::new(Level::Connection, false, true, false)
    }

    pub fn new_default_session() -> Self {
        Self::new(Level::Session, true, false, true)
    }

    pub fn new_default_packet() -> Self {
        Self::new(Level::Packet, false, false, false)
    }

    pub fn should_deliver(&self, filter_layer: FilterLayer, pred: &Predicate) -> bool {
        match self.level {
            Level::Packet => {
                match filter_layer {
                    FilterLayer::PacketContinue => {
                        return pred.on_packet();
                    }
                    FilterLayer::Protocol => {
                        return pred.on_proto();
                    }
                    FilterLayer::Session => {
                        return pred.on_session();
                    }
                    _ => {
                        // Packet: Action-only
                        // Conn. deliver: packets delivered when matched, not at termination
                        return false;
                    }
                }
            }
            Level::Connection => {
                return matches!(filter_layer, FilterLayer::ConnectionDeliver);
            }
            Level::Session => {
                return matches!(filter_layer, FilterLayer::Session);
            }
            Level::Streaming => {
                todo!();
            }
        }
    }

    pub fn packet_continue(&self) -> DataTypeAction {
        let mut if_matched = Actions::new();
        let mut if_matching = Actions::new();

        match self.level {
            Level::Packet => {
                // If filter terminally matched, packet delivered in CB
            }
            _ => {
                // Forward to conn tracker
                if_matched.data |= ActionData::PacketContinue;
                if_matching.data |= ActionData::PacketContinue;
            }
        }
        DataTypeAction {
            if_matched,
            if_matching
        }    
    }

    // First packet in connection
    pub fn packet_filter(&self) -> DataTypeAction {
        let mut if_matched = Actions::new();
        let mut if_matching = Actions::new();
        match self.level {
            Level::Packet => {
                // Terminal match should have already been delivered
                if_matching.data |= ActionData::PacketTrack | ActionData::ProtoFilter;
            }
            Level::Connection => {
                // Track connection metadata
                if_matched.data |= ActionData::ConnDataTrack;
                if_matched.terminal_actions |= ActionData::ConnDataTrack;
                // Track data, apply next filter
                if_matching.data |= ActionData::ConnDataTrack | ActionData::ProtoFilter;
            }
            Level::Session => {
                // Start parsing, deliver session when parsed
                if_matched.data |= ActionData::ProtoProbe |
                                   ActionData::SessionDeliver;
                if_matched.terminal_actions |= if_matched.data.clone();
                // Apply next filter (implicitly probe for protocol)
                if_matching.data |= ActionData::ProtoFilter;
            }
            Level::Streaming => todo!()
        }
        DataTypeAction {
            if_matched,
            if_matching
        }  
    }

    pub fn proto_filter(&self) -> DataTypeAction {
        let mut if_matched = Actions::new();
        let mut if_matching = Actions::new();
        match self.level {
            Level::Packet => {
                if_matched.data |= ActionData::PacketDeliver;
                if_matched.terminal_actions |= ActionData::PacketDeliver;
                // Continue buffering packets, apply next filter
                if_matching.data |= ActionData::PacketTrack |
                                    ActionData::SessionFilter;
            }
            Level::Connection => {
                if_matched.data |= ActionData::ConnDataTrack;
                if_matched.terminal_actions |= ActionData::ConnDataTrack;
                // Continue tracking, apply next filter
                if_matching.data |= ActionData::ConnDataTrack | ActionData::SessionFilter;
            }
            Level::Session => {
                // Deliver session when parsed (implicitly continue parsing)
                if_matched.data |= ActionData::SessionDeliver;
                if_matched.terminal_actions |= ActionData::SessionDeliver;
                // Apply next filter (implicitly continue parsing)
                if_matching.data |= ActionData::SessionFilter;
            }
            Level::Streaming => todo!()
        }
        DataTypeAction {
            if_matched,
            if_matching
        }
    }

    pub fn session_filter(&self) -> DataTypeAction {
        let mut if_matched = Actions::new();
        match self.level {
            Level::Packet => {
                if_matched.data |= ActionData::PacketDeliver;
                if_matched.terminal_actions |= ActionData::PacketDeliver;
            }
            Level::Connection => {
                if_matched.data |= ActionData::ConnDataTrack | 
                                   // Re-apply session filter at conn. term
                                   ActionData::SessionTrack;
                if_matched.terminal_actions |= if_matched.data.clone();
            }
            Level::Session => {
                // Will be delivered in session filter
            }
            Level::Streaming => todo!()
        }
        DataTypeAction {
            if_matched,
            if_matching: Actions::new(), // last filter applied (until streaming impl.)
        }
    }

    pub fn with_term_filter(&self, filter_layer: FilterLayer) -> Actions {
        match filter_layer {
            FilterLayer::PacketContinue => {
                return self.packet_continue().if_matched;
            }
            FilterLayer::Packet => {
                return self.packet_filter().if_matched;
            }
            FilterLayer::Protocol => {
                return self.proto_filter().if_matched;
            }
            FilterLayer::Session => {
                return self.session_filter().if_matched;
            }
            FilterLayer::ConnectionDeliver => {
                // No actions
                return Actions::new();
            }
        }
    }

    pub fn with_nonterm_filter(&self, filter_layer: FilterLayer) -> Actions {
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
            FilterLayer::ConnectionDeliver => { }
        }
        actions
    }
}