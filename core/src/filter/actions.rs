use proc_macro2::Span;
use quote::{ToTokens, quote};
use std::str::FromStr;
use std::hash::{Hash, Hasher};

/// Failed to parse from string
#[derive(Debug, PartialEq, Eq)]
pub struct ParseBitmaskError;

// Packet-level actions applied to determine whether a packet should be
// continued through the filtering pipeline.
bitmask! {
    #[derive(Debug, Hash)]
    pub mask PacketActions: u8 where flags Packet {
        Track   = 0x1 << 0,
        Deliver = 0x1 << 1,
        Unsure  = 0x1 << 2,
    }
}

impl ToTokens for PacketActions {

    fn to_tokens(&self, tokens: &mut proc_macro2::TokenStream) {
        let mask = syn::LitInt::new(&self.mask.to_string(), Span::call_site());
        tokens.extend( quote! { PacketActions::from(#mask) } );
    }
}

impl From<u8> for PacketActions {
    fn from(value: u8) -> Self {
        Self {
            mask: value
        }
    }
}

impl FromStr for Packet {
    type Err = ParseBitmaskError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s_trim = match s.starts_with("Packet::") {
            true => s.strip_prefix("Packet::").unwrap(),
            false => s
        };
        
        match s_trim { 
            "Track" => Ok(Packet::Track),
            "Deliver" => Ok(Packet::Deliver),
            "Unsure" => Ok(Packet::Unsure),
            _ => Result::Err(ParseBitmaskError)
        }
    }
}

impl Hash for Packet {
    fn hash<H: Hasher>(&self, state: &mut H) {
        PacketActions::from(*self).hash(state);
    }
}

impl FromStr for PacketActions {
    type Err = ParseBitmaskError;
    
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut result = PacketActions::none();
        let split = s.split("|");
        for action_str in split {
            if let Ok(a) = Packet::from_str(action_str.trim()) {
                result |= a;
            } else {
                return Result::Err(ParseBitmaskError);
            }
        }
        Ok(result)
    }
}

// All possible data actions to perform following any filter stage.
bitmask! {
    // Possible actions following a filter
    #[derive(Debug, Hash)]
    pub mask ActionData: u32 where flags ActionFlags {
        // Deliver frame directly to callback(s)
        FrameDeliver        = 0x1 << 1,
        // Track connection metadata
        ConnDataTrack       = 0x1 << 2,
        // Buffer frames for future (possible) delivery
        FrameTrack          = 0x1 << 3, 
        // Parse application-layer protocol
        ConnParse           = 0x1 << 4,
        // Apply connection-level filter
        ConnFilter          = 0x1 << 5,
        // Parse all session data (following conn filter)
        SessionParse        = 0x1 << 6,
        // Apply session-level filter
        SessionFilter       = 0x1 << 7, 
        // Buffer session for future delivery
        SessionTrack        = 0x1 << 8, 
        // Deliver session to callback(s)
        SessionDeliver      = 0x1 << 9,
        // Deliver buffered frames (frame subscription newly matched)
        FrameDrain          = 0x1 << 10,
        // Track connection (any data)?
        ConnTracked         = 0x1 << 11,
        // General request to track a connection (used by packet filter)?
        TrackAny            = 0x1 << 12,
    }
}

impl Hash for ActionFlags {
    fn hash<H: Hasher>(&self, state: &mut H) {
        ActionData::from(*self).hash(state);
    }
}

impl FromStr for ActionFlags {
    type Err = ParseBitmaskError;

    // TODO better way to do this? 
    // EnumString/strum macros only for enums/structs
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut s_trim = match s.starts_with("ActionFlags::") {
            true => s.strip_prefix("ActionFlags::").unwrap(),
            false => s
        };
        s_trim = match s_trim.ends_with("(T)") {
            true => s_trim.strip_suffix("(T)").unwrap().trim(),
            false => s_trim,
        };
        match s_trim {
            "FrameDeliver" => Ok(ActionFlags::FrameDeliver),
            "ConnDataTrack" => Ok(ActionFlags::ConnDataTrack),
            "FrameTrack" => Ok(ActionFlags::FrameTrack),
            "ConnParse" => Ok(ActionFlags::ConnParse),
            "ConnFilter" => Ok(ActionFlags::ConnFilter),
            "SessionParse" => Ok(ActionFlags::SessionParse),
            "SessionFilter" => Ok(ActionFlags::SessionFilter),
            "SessionTrack" => Ok(ActionFlags::SessionTrack),
            "SessionDeliver" => Ok(ActionFlags::SessionDeliver),
            "FrameDrain" => Ok(ActionFlags::FrameDrain),
            "ConnTracked" => Ok(ActionFlags::ConnTracked),
            "TrackAny" => Ok(ActionFlags::TrackAny),
            _ => Result::Err(ParseBitmaskError)
        }  
    }
}

impl FromStr for ActionData {
    type Err = ParseBitmaskError;
    
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut result = ActionData::none();
        let split = s.split("|");
        for action_str in split {
            if let Ok(a) = ActionFlags::from_str(action_str.trim()) {
                result |= a;
            } else {
                return Result::Err(ParseBitmaskError);
            }
        }
        Ok(result)
    }
}

impl ToTokens for ActionData {

    fn to_tokens(&self, tokens: &mut proc_macro2::TokenStream) {
        let mask = syn::LitInt::new(&self.mask.to_string(), Span::call_site());
        tokens.extend( quote! { ActionData::from(#mask) } );
    }
}

impl From<u32> for ActionData {
    fn from(value: u32) -> Self {
        Self {
            mask: value
        }
    }
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

impl ToTokens for Actions {

    fn to_tokens(&self, tokens: &mut proc_macro2::TokenStream) {
        let data = self.data.clone();
        let terminal_actions = self.terminal_actions.clone();
        tokens.extend(quote! { 
            Actions {
                data: #data,
                terminal_actions: #terminal_actions
            }
        } ); // tmp
    }
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

impl FromStr for Actions {
    type Err = ParseBitmaskError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut result = Actions::new();
        let split = s.split("|");
        for action_str in split {
            let terminal = action_str.contains("(T)");
            if let Ok(a) = ActionFlags::from_str(action_str.trim()) {
                result.data |= a;
                if terminal { 
                    result.terminal_actions |= a; 
                }
            } else {
                return Result::Err(ParseBitmaskError);
            }
        }
        Ok(result)
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

        // Parsing
        assert!(ActionFlags::from_str("FrameDeliver").unwrap() == ActionFlags::FrameDeliver);
        assert!(ActionFlags::from_str("error!") == Result::Err(ParseBitmaskError));
        assert!(Packet::from_str("Track").unwrap() == Packet::Track);

        assert!(PacketActions::from_str("Track | Deliver").unwrap() == Packet::Track | Packet::Deliver);
        assert!(ActionData::from_str("ActionFlags::ConnDataTrack").unwrap() == ActionFlags::ConnDataTrack.into());
        assert!(Actions::from_str("ConnDataTrack (T) | ConnParse").unwrap() == 
                    Actions { 
                        data: ActionFlags::ConnDataTrack | ActionFlags::ConnParse,
                        terminal_actions: ActionFlags::ConnDataTrack.into() 
                    }
                );
    }
}