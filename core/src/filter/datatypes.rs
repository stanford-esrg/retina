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
    // [note] May want other things?
}

// [TODO] allow for more complex datatypes by 
// referring to needs_parse, needs_update
pub struct DataTypeAction {
    pub if_matched: Actions,
    pub if_matching: Actions,
}

impl DataType {
    pub fn new(level: Level, needs_parse: bool, needs_update: bool) -> Self {
        Self {
            level,
            needs_parse,
            needs_update
        }
    }

    pub fn packet_continue(&self) -> DataTypeAction {
        let mut if_matched = Actions::new();
        let mut if_matching = Actions::new();

        match self.level {
            Level::Packet => {
                // If filter (terminally) matched, packet delivered right away
                if_matched.data |= ActionData::PacketDeliver;
                // Else, buffer packet until filter matches
                if_matching.data |= ActionData::PacketTrack;
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
                // TODO dep. on where delivery/track happens
                // Ideally, won't be re-checked
                if_matched.data |= ActionData::PacketDeliver;
                if_matching.data |=  ActionData::PacketTrack;
                panic!("Packet datatypes not (fully) implemented");
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
                // Deliver data
                if_matched.data |= ActionData::PacketDeliver | 
                                   ActionData::PacketDrain;
                if_matched.terminal_actions |= if_matched.data.clone();
                // Continue buffering packets, apply next filter
                if_matching.data |= ActionData::PacketTrack | 
                                    ActionData::SessionFilter;
                panic!("Packet datatypes not (fully) implemented");
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
                if_matched.data |= ActionData::PacketDrain;
                if_matched.terminal_actions |= ActionData::PacketDeliver | 
                                               ActionData::PacketDrain;
                panic!("Packet datatypes not (fully) implemented");
            }
            Level::Connection => {
                if_matched.data |= ActionData::ConnDataTrack;
                if_matched.terminal_actions |= ActionData::ConnDataTrack;
            }
            Level::Session => {
                if_matched.data |= ActionData::SessionDeliver;
                if_matched.terminal_actions |= ActionData::SessionDeliver;
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
            FilterLayer::Connection => {
                return self.proto_filter().if_matched;
            }
            FilterLayer::Session => {
                return self.session_filter().if_matched;
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
            FilterLayer::Connection => {
                // Apply next filter
                actions.data |= ActionData::SessionFilter;
                actions.update(&self.proto_filter().if_matching);
            }
            FilterLayer::Session => {
                actions.update(&self.session_filter().if_matching);
            }
        }
        actions
    }
}