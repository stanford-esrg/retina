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
        None    = 0x0 << 0,
        Track   = 0x1 << 0,
        Deliver = 0x1 << 1,
        Unsure  = 0x1 << 2, // HW not sure what to do, reapply SW pkt filter
    } // TODO idea is that this is done in HW via pkt marking
}
// TODO better approach?
static PACKET_ACTIONS: [Packet; 3] = [ Packet::Track, Packet::Deliver, Packet::Unsure ];

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

impl ToString for Packet {
    fn to_string(&self) -> String {
        match self {
            Packet::None => "P::None".into(),
            Packet::Track => "P::Track".into(),
            Packet::Deliver => "P::Deliver".into(),
            Packet::Unsure => "P::Unsure".into(),
        }
    }
}

impl ToString for PacketActions {
    fn to_string(&self) -> String {
        let mut out = String::from("");
        for flag in PACKET_ACTIONS {
            if self.contains(flag) {
                if out != "" { out += " | "}
                out.push_str(&flag.to_string());
            }
        }
        if out == "" { out = Packet::None.to_string(); }
        out
    }
}

impl FromStr for Packet {
    type Err = ParseBitmaskError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut s_trim = match s.starts_with("Packet::") {
            true => s.strip_prefix("Packet::").unwrap(),
            false => s
        };
        s_trim = match s_trim.starts_with("P::") {
            true => s_trim.strip_prefix("P::").unwrap(),
            false => s_trim
        };
        
        match s_trim { 
            "None" => Ok(Packet::None),
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
        // Placeholder to add "no-op" nodes to filter tree
        None                = 0x0 << 0,
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
        // TODO better way to do this [conn matched, session to be delivered]
        SessionDeliverConn = 0x1 << 13,
        SessionTrackConn   = 0x1 << 14,

        // Pkt action (if HW unsure?)
        FrameContinue      = 0x1 << 15,
    }
}
static FILTER_ACTIONS: [ActionFlags; 14] = [ 
    ActionFlags::FrameDeliver,
    ActionFlags::ConnDataTrack, 
    ActionFlags::FrameTrack,
    ActionFlags::ConnParse,
    ActionFlags::ConnFilter,
    ActionFlags::SessionParse,
    ActionFlags::SessionFilter,
    ActionFlags::SessionTrack,
    ActionFlags::SessionDeliver,
    ActionFlags::FrameDrain,
    ActionFlags::ConnTracked,
    ActionFlags::TrackAny,
    ActionFlags::SessionDeliverConn,
    ActionFlags::SessionTrackConn,
];

impl ToString for ActionFlags {
    fn to_string(&self) -> String {
        match self {
            ActionFlags::None => "A::None".into(),
            ActionFlags::FrameDeliver => "A::FrameDeliver".into(),
            ActionFlags::ConnDataTrack => "A::ConnDataTrack".into(),
            ActionFlags::FrameTrack => "A::FrameTrack".into(),
            ActionFlags::ConnParse => "A::ConnParse".into(),
            ActionFlags::ConnFilter => "A::ConnFilter".into(),
            ActionFlags::SessionParse => "A::SessionParse".into(),
            ActionFlags::SessionFilter => "A::SessionFilter".into(),
            ActionFlags::SessionTrack => "A::SessionTrack".into(),
            ActionFlags::SessionDeliver => "A::SessionDeliver".into(),
            ActionFlags::FrameDrain => "A::FrameDrain".into(),
            ActionFlags::ConnTracked => "A::ConnTracked".into(),
            ActionFlags::TrackAny => "A::TrackAny".into(),
            ActionFlags::SessionDeliverConn => "A::SessionDeliverConn".into(),
            ActionFlags::SessionTrackConn => "A::SessionTrackConn".into(),
            ActionFlags::FrameContinue => "A::FrameContinue".into(),
        }
    }
}

impl ToString for Actions {
    fn to_string(&self) -> String {
        let mut out = String::from("");
        for flag in FILTER_ACTIONS {
            if self.data.contains(flag) {
                if out != "" { out += " | "}
                out.push_str(&flag.to_string());
                if self.terminal_actions.contains(flag) {
                    out.push_str(&" (T)");
                }
            }
        }
        if out == "" {
            out = ActionFlags::None.to_string();
        }
        out
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
        s_trim = match s_trim.starts_with("A::") {
            true => s_trim.strip_prefix("A::").unwrap(),
            false => s_trim
        };
        
        match s_trim {
            "None"         => Ok(ActionFlags::None),
            "FrameDeliver" => Ok(ActionFlags::FrameDeliver),
            "ConnDataTrack" => Ok(ActionFlags::ConnDataTrack),
            "FrameTrack" => Ok(ActionFlags::FrameTrack),
            "ConnParse" => Ok(ActionFlags::ConnParse),
            "ConnFilter" => Ok(ActionFlags::ConnFilter),
            "SessionParse" => Ok(ActionFlags::SessionParse),
            "SessionFilter" => Ok(ActionFlags::SessionFilter),
            "SessionTrack" => Ok(ActionFlags::SessionTrack),
            "SessionDeliver" => Ok(ActionFlags::SessionDeliver),
            "SessionDeliverConn" => Ok(ActionFlags::SessionDeliverConn),
            "SessionTrackConn" => Ok(ActionFlags::SessionTrackConn),
            "FrameDrain" => Ok(ActionFlags::FrameDrain),
            "ConnTracked" => Ok(ActionFlags::ConnTracked),
            "TrackAny" => Ok(ActionFlags::TrackAny),
            "FrameContinue" => Ok(ActionFlags::FrameContinue),
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
                             ActionFlags::ConnParse |
                             ActionFlags::ConnFilter | 
                             ActionFlags::SessionFilter)
    }

    #[inline]
    pub fn drop(&self) -> bool {
        self.data.is_none() && self.terminal_actions.is_none()
    }

    #[inline]
    pub fn session_deliver(&self) -> bool {
        self.data.intersects(ActionFlags::SessionDeliver | 
                             ActionFlags::SessionTrack |
                             ActionFlags::SessionDeliverConn |
                             ActionFlags::SessionTrackConn)
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
        self.data.intersects(ActionFlags::ConnParse | ActionFlags::ConnFilter)
    }

    #[inline]
    pub fn session_parse(&self) -> bool {
        self.data.intersects(ActionFlags::SessionParse | ActionFlags::SessionFilter)
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
        let pkt = Packet::Track | Packet::Unsure;
        assert!(pkt.to_string() == "P::Track | P::Unsure" ||
                pkt.to_string() == "P::Unsure | P::Track");

        let mut actions = Actions::new();
        actions.data.set(ActionFlags::ConnParse);
        actions.data.set(ActionFlags::ConnDataTrack);
        actions.terminal_actions.set(ActionFlags::ConnDataTrack);
        println!("{}", actions.to_string());
        assert!(actions.to_string() == "A::ConnDataTrack (T) | A::ConnParse" || 
                actions.to_string() == "A::ConnParse | A::ConnDataTrack (T)");
    }
}