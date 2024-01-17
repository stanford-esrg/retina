bitmask! {
    #[derive(Debug)]
    pub mask PacketActions: u8 where flags Packet {
        Track   = 0x1 << 0,
        Deliver = 0x1 << 1,
        Unsure  = 0x1 << 2,
    }
}

impl From<u8> for PacketActions {
    fn from(value: u8) -> Self {
        Self {
            mask: value
        }
    }
}

// All possible data actions to perform following a filter.
bitmask! {
    // Possible actions following a filter
    #[derive(Debug)]
    pub mask ActionData: u32 where flags ActionFlags {
        // Deliver frame directly to callback(s)
        FrameDeliver        = 0x1 << 0,
        // Track connection metadata
        ConnDataTrack       = 0x1 << 1,
        // Buffer frames for future (possible) delivery
        FrameTrack          = 0x1 << 2, 
        // Parse application-layer protocol
        ConnParse           = 0x1 << 3,
        // Apply connection-level filter
        ConnFilter          = 0x1 << 4,
        // Parse all session data (following conn filter)
        SessionParse        = 0x1 << 5,
        // Apply session-level filter
        SessionFilter       = 0x1 << 6, 
        // Buffer session for future delivery
        SessionTrack        = 0x1 << 7, 
        // Deliver session to callback(s)
        SessionDeliver      = 0x1 << 8,
        // General request to track a connection (used by packet filter)?
        TrackAny            = 0x1 << 9,
        // Deliver buffered frames (frame subscription newly matched)
        FrameDrain          = 0x1 << 10,
        // Track connection (any data)?
        ConnTracked         = 0x1 << 11
    }
}

impl From<u32> for ActionData {
    fn from(value: u32) -> Self {
        Self {
            mask: value
        }
    }
}

#[derive(Debug, Clone)]
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
        self.data.intersects(ActionFlags::ConnDataTrack | 
                             ActionFlags::FrameTrack | 
                             ActionFlags::ConnParse |
                             ActionFlags::ConnFilter |
                             ActionFlags::ConnTracked)
    }

    /// Conn tracker must deliver PDU to 
    #[inline]
    pub fn track_pdu(&self) -> bool {
        self.data.intersects(ActionFlags::ConnDataTrack | 
                             ActionFlags::FrameTrack)
    }

    #[inline]
    pub fn parse_any(&self) -> bool {
        self.data.intersects(ActionFlags::SessionParse | 
                             ActionFlags::ConnParse)
    }

    #[inline]
    pub fn drop(&self) -> bool {
        self.data.is_none() && self.terminal_actions.is_none()
    }

    #[inline]
    pub fn session_deliver(&self) -> bool {
        self.data.intersects(ActionFlags::SessionDeliver | 
                             ActionFlags::SessionTrack)
    }

    #[inline]
    pub fn session_delivered(&mut self) {
        if self.data.contains(ActionFlags::SessionTrack) {
            self.terminal_actions.set(ActionFlags::ConnTracked);
            self.data.set(ActionFlags::ConnTracked);
        }
        self.data.unset(ActionFlags::SessionDeliver | 
                        ActionFlags::SessionTrack);
        self.terminal_actions.unset(ActionFlags::SessionDeliver | 
                                    ActionFlags::SessionTrack);
    }

    #[inline]
    pub fn apply_session_filter(&mut self) -> bool {
        self.data.contains(ActionFlags::SessionFilter)
    }

    #[inline]
    pub fn session_probe(&self) -> bool {
        self.data.contains(ActionFlags::ConnParse)
    }

    #[inline]
    pub fn session_parse(&self) -> bool {
        self.data.contains(ActionFlags::SessionParse)
    }

    #[inline]
    pub fn session_clear_parse(&mut self) {
        let mask = ActionFlags::SessionParse | ActionFlags::SessionFilter;
        self.data.unset(mask);
        self.terminal_actions.unset(mask); // TODOTR may not be necessary
    }

    #[inline]
    pub fn connection_matched(&mut self) -> bool {
        self.terminal_actions.intersects(ActionFlags::ConnDataTrack | 
                                       ActionFlags::FrameTrack |
                                       ActionFlags::SessionTrack |
                                       ActionFlags::ConnTracked)
    }

    #[inline]
    pub fn clear(&mut self) {
        self.terminal_actions = ActionData::none();
        self.data = ActionData::none();
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
        actions.data.set(ActionFlags::ConnParse);

        // Check that an action is set/not set
        assert!(actions.data.contains(ActionFlags::ConnParse));
        assert!(!actions.data.contains(ActionFlags::FrameDeliver));

        // Check intersection
        assert!(actions.needs_conntrack());

        // Set, clear, and check actions by bitmask
        let frame_mask = ActionFlags::FrameTrack | 
                                     ActionFlags::FrameDeliver;
        actions.data.set(frame_mask);
        assert!(actions.data.contains(frame_mask));
        actions.data.unset(frame_mask);
        
        // Clear an action (or set of actions)
        actions.data.unset(ActionFlags::ConnParse);

        // Check that no actions are requested
        assert!(actions.drop());
    }
}