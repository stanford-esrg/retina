use bitmask_enum::bitmask;

#[bitmask]
#[bitmask_config(vec_debug)]
pub enum ActionData {
    // Packet actions //
    PacketContinue,   // Forward new packet to connection tracker

    // Connection/session actions // 

    ProtoProbe,       // Probe application-layer protocol 
    ProtoFilter,      // Apply protocol-level filter

    SessionFilter,    // Apply session-level filter
    SessionDeliver,   // Deliver session when parsed

    ConnDataTrack,    // Track connection metadata
    PacketTrack,      // Buffer frames for future possible delivery

    PacketDrain,      // Deliver buffered packets to CB(s) (new match)

    // \note Session and packet delivery happen within filters.
    // \note This assumes that each callback has exactly one "layer"
}

#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct Actions {
    /// All actions (terminal and non-terminal) that should
    /// be performed following the application of a filter.
    pub data: ActionData,
    /// All actions that should continue to be performed
    /// regardless of what the next filter returns
    /// E.g., if a terminal match for a connection-level filter
    /// occurs at the packet layer, we should continue tracking
    /// the connection without re-applying that filter.
    pub terminal_actions: ActionData,
}

impl Actions {

    /// Create an empty Actions bitmask
    pub fn new() -> Self {
        Self {
            data: ActionData::none(),
            terminal_actions: ActionData::none()
        }
    }

    /// Store the result of a new filter
    #[inline]
    pub fn update(&mut self, actions: &Actions) {
        self.data = self.terminal_actions | actions.data;
        self.terminal_actions |= actions.terminal_actions;
    }

    /// Packet action handler must deliver this to conn tracker
    #[inline]
    pub fn needs_conntrack(&self) -> bool {
        self.data.intersects(ActionData::PacketContinue)
    }

    /// Conn tracker must deliver PDU to tracked data
    #[inline]
    pub fn track_pdu(&self) -> bool {
        self.data.intersects(
            ActionData::ConnDataTrack
        )
    }

    /// App-layer probing or parsing should be applied
    #[inline]
    pub fn parse_any(&self) -> bool {
        self.data.intersects(ActionData::ProtoProbe | 
                             ActionData::ProtoFilter |
                             ActionData::SessionFilter |
                             ActionData::SessionDeliver)
    }

    #[inline]
    pub fn drop(&self) -> bool {
        self.data.is_none() && self.terminal_actions.is_none()
    }

    #[inline]
    pub fn apply_session_filter(&mut self) -> bool {
        self.data.contains(ActionData::SessionFilter)
    }

    #[inline]
    pub fn apply_proto_filter(&mut self) -> bool {
        self.data.contains(ActionData::ProtoFilter)
    }

    #[inline]
    pub fn session_probe(&self) -> bool {
        self.data.intersects(ActionData::ProtoProbe | 
                             ActionData::ProtoFilter)
    }

    #[inline]
    pub fn session_parse(&self) -> bool {
        self.data.intersects(ActionData::SessionDeliver | 
                             ActionData::SessionFilter)
    }

    #[inline]
    pub fn session_deliver(&mut self) -> bool {
        self.data.contains(ActionData::SessionDeliver)
    }

    /// After parsing a session, the framework must decide whether to continue
    /// probing for sessions depending on the protocol
    /// If no further parsing is required (e.g., TLS Handshake)
    #[inline]
    pub fn session_clear_parse(&mut self) {
        self.data ^= ActionData::SessionFilter | ActionData::SessionDeliver;
        self.terminal_actions ^= ActionData::SessionFilter | ActionData::SessionDeliver;
    }

    /// After parsing
    /// If further sessions may be expected (e.g., HTTP), need to probe
    /// and filter for them again. 
    pub fn session_set_probe(&mut self) {
        self.clear_mask(ActionData::SessionFilter | ActionData::SessionDeliver);
        self.data |= ActionData::ProtoProbe | ActionData::ProtoFilter;
        /* 
         * Note: it could be inefficient to re-apply the proto filter
         *       (protocol was already ID'd). However, this makes it easier
         *       to ensure that correct actions are (re-)populated 
         *       protocol filter if we already know the protocol.
         *       This also allows for extensibility to nested protocols.
         */
    }

    #[inline]
    pub fn session_clear_deliver(&mut self) {
        self.clear_mask(ActionData::SessionDeliver);
    }

    #[inline]
    pub fn connection_matched(&mut self) -> bool {
        self.terminal_actions.intersects(ActionData::ConnDataTrack)
    }

    #[inline]
    pub fn clear(&mut self) {
        self.terminal_actions = ActionData::none();
        self.data = ActionData::none();
    }

    #[inline]
    pub fn clear_mask(&mut self, mask: ActionData) {
        self.data ^= mask;
        self.terminal_actions ^= mask;
    }

}


/// Sample usage of bitmask! macro
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    pub fn test_actions() {
        let mut actions = Actions::new();
        // Set an action
        actions.data |= ActionData::PacketContinue;

        // Check that an action is set/not set
        assert!(!actions.data.contains(ActionData::SessionFilter));
        assert!(actions.data.contains(ActionData::PacketContinue));

        // Check intersection
        assert!(actions.needs_conntrack());

        // Set, clear, and check actions by bitmask
        let frame_mask = ActionData::PacketTrack | 
                                     ActionData::ConnDataTrack;
        actions.data |= frame_mask;
        assert!(actions.data.contains(frame_mask));
        actions.data ^= frame_mask;
        
        // Clear an action (or set of actions)
        actions.data ^= ActionData::SessionFilter;

        // Check that no actions are requested
        assert!(actions.drop());
    }
}