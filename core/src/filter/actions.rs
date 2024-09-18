use bitmask_enum::bitmask;

#[bitmask]
#[bitmask_config(vec_debug)]
pub enum ActionData {
    // Packet actions //
    PacketContinue, // Forward new packet to connection tracker
    PacketDeliver,  // Deliver packet to CB

    // Connection/session actions //
    ProtoProbe,  // Probe application-layer protocol
    ProtoFilter, // Apply protocol-level filter

    SessionFilter,  // Apply session-level filter
    SessionDeliver, // Deliver session when parsed
    SessionTrack,   // Store session in tracked data
    // Deliver or use to check a filter at conn. termination
    UpdatePDU,            // `Update` method should be invoked pre-reassembly
    ReassembledUpdatePDU, // `Update` method should be invoked post-reassembly
    PacketTrack,          // Buffer frames for future possible delivery

    ConnDeliver,          // Deliver connection on termination

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

impl Default for Actions {
    fn default() -> Self {
        Self::new()
    }
}

impl Actions {
    /// Create an empty Actions bitmask
    pub fn new() -> Self {
        Self {
            data: ActionData::none(),
            terminal_actions: ActionData::none(),
        }
    }

    /// Store the result of a new filter
    /// Used at runtime after application of next filter
    #[inline]
    pub fn update(&mut self, actions: &Actions) {
        self.data = self.terminal_actions | actions.data;
        self.terminal_actions |= actions.terminal_actions;
    }

    /// Combine terminal and non-terminal actions
    /// Used for building a filter
    #[inline]
    pub fn push(&mut self, actions: &Actions) {
        self.data |= actions.data;
        self.terminal_actions |= actions.terminal_actions;
    }

    /// Update self to contain only actions not in `actions`
    #[inline]
    pub fn clear_intersection(&mut self, actions: &Actions) {
        self.data &= actions.data.not();
        self.terminal_actions &= actions.data.not();
    }

    /// Add actions during (while applying) a filter
    #[inline]
    pub fn add_actions(&mut self, actions: &Actions) {
        self.data |= actions.data;
        self.terminal_actions |= actions.terminal_actions;
    }

    /// Packet action handler must deliver this to conn tracker
    #[inline]
    pub fn needs_conntrack(&self) -> bool {
        self.data.intersects(ActionData::PacketContinue)
    }

    /// Conn tracker must deliver PDU to tracked data
    #[inline]
    pub fn update_pdu(&self, reassembled: bool) -> bool {
        match reassembled {
            false => self.data.intersects(ActionData::UpdatePDU),
            true => self.data.intersects(ActionData::ReassembledUpdatePDU),
        }
    }

    #[inline]
    pub fn buffer_frame(&self) -> bool {
        self.data.intersects(ActionData::PacketTrack)
    }

    /// App-layer probing or parsing should be applied
    #[inline]
    pub fn parse_any(&self) -> bool {
        self.data.intersects(
            ActionData::ProtoProbe
                | ActionData::ProtoFilter
                | ActionData::SessionFilter
                | ActionData::SessionDeliver
                | ActionData::SessionTrack,
        )
    }

    #[inline]
    pub fn reassemble(&self) -> bool {
        self.parse_any() || self.buffer_frame() || self.update_pdu(true)
    }

    #[inline]
    pub fn drop(&self) -> bool {
        self.data.is_none() && self.terminal_actions.is_none()
    }

    #[inline]
    pub fn apply_session_filter(&mut self) -> bool {
        // \note deliver filter is in session filter
        self.data.intersects(ActionData::SessionFilter |
                             ActionData::SessionDeliver)
    }

    #[inline]
    pub fn apply_proto_filter(&mut self) -> bool {
        self.data.contains(ActionData::ProtoFilter)
    }

    #[inline]
    pub fn session_probe(&self) -> bool {
        self.data
            .intersects(ActionData::ProtoProbe | ActionData::ProtoFilter)
    }

    #[inline]
    pub fn session_parse(&self) -> bool {
        self.data.intersects(
            ActionData::SessionDeliver | ActionData::SessionFilter | ActionData::SessionTrack,
        )
    }

    #[inline]
    pub fn session_track(&self) -> bool {
        self.data.intersects(ActionData::SessionTrack)
    }

    #[inline]
    pub fn packet_deliver(&self) -> bool {
        self.data.intersects(ActionData::PacketDeliver)
    }

    /// After parsing a session, the framework must decide whether to continue
    /// probing for sessions depending on the protocol
    /// If no further parsing is required (e.g., TLS Handshake), this method
    /// should be invoked.
    #[inline]
    pub fn session_clear_parse(&mut self) {
        self.clear_mask(
            ActionData::SessionFilter | ActionData::SessionDeliver | ActionData::SessionTrack,
        );
    }

    /// Some app-layer protocols revert to probing after session is parsed
    /// (e.g., in case of encapsulation)
    pub fn session_set_probe(&mut self) {
        self.clear_mask(
            ActionData::SessionFilter | ActionData::SessionDeliver | ActionData::SessionTrack,
        );
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
    pub fn connection_matched(&self) -> bool {
        self.terminal_actions
            .intersects(ActionData::ConnDeliver)
    }

    #[inline]
    pub fn clear(&mut self) {
        self.terminal_actions = ActionData::none();
        self.data = ActionData::none();
    }

    #[inline]
    pub fn clear_mask(&mut self, mask: ActionData) {
        self.data &= mask.not();
        self.terminal_actions &= mask.not();
    }
}

use proc_macro2::{Ident, Span};
use quote::{quote, ToTokens};
use std::str::FromStr;

#[allow(clippy::to_string_trait_impl)]
impl FromStr for ActionData {
    type Err = core::fmt::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "PacketContinue" => Ok(ActionData::PacketContinue),
            "PacketDeliver" => Ok(ActionData::PacketDeliver),
            "ProtoProbe" => Ok(ActionData::ProtoProbe),
            "ProtoFilter" => Ok(ActionData::ProtoFilter),
            "SessionFilter" => Ok(ActionData::SessionFilter),
            "SessionDeliver" => Ok(ActionData::SessionDeliver),
            "SessionTrack" => Ok(ActionData::SessionTrack),
            "UpdatePDU" => Ok(ActionData::UpdatePDU),
            "ReassembledUpdatePDU" => Ok(ActionData::ReassembledUpdatePDU),
            "PacketTrack" => Ok(ActionData::PacketTrack),
            "ConnDeliver" => Ok(ActionData::ConnDeliver),
            _ => Result::Err(core::fmt::Error),
        }
    }
}

#[allow(clippy::to_string_trait_impl)]
impl ToString for ActionData {
    fn to_string(&self) -> String {
        match *self {
            ActionData::PacketContinue => "PacketContinue".into(),
            ActionData::PacketDeliver => "PacketDeliver".into(),
            ActionData::ProtoProbe => "ProtoProbe".into(),
            ActionData::ProtoFilter => "ProtoFilter".into(),
            ActionData::SessionFilter => "SessionFilter".into(),
            ActionData::SessionDeliver => "SessionDeliver".into(),
            ActionData::SessionTrack => "SessionTrack".into(),
            ActionData::UpdatePDU => "UpdatePDU".into(),
            ActionData::ReassembledUpdatePDU => "ReassembledUpdatePDU".into(),
            ActionData::PacketTrack => "PacketTrack".into(),
            ActionData::ConnDeliver => "ConnDeliver".into(),
            _ => panic!("Unknown ActionData"),
        }
    }
}

impl ToTokens for ActionData {
    fn to_tokens(&self, tokens: &mut proc_macro2::TokenStream) {
        let name_ident = Ident::new(&self.to_string(), Span::call_site());
        let enum_ident = Ident::new("ActionData", Span::call_site());
        tokens.extend(quote! { #enum_ident::#name_ident });
    }
}

impl FromStr for Actions {
    type Err = core::fmt::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut result = Actions::new();
        let split = s.split("|");
        for str in split {
            let terminal = str.contains("(T)");
            let action_str = str.replace("(T)", "");
            if let Ok(a) = ActionData::from_str(action_str.trim()) {
                result.data |= a;
                if terminal {
                    result.terminal_actions |= a;
                }
            } else {
                return Result::Err(core::fmt::Error);
            }
        }
        Ok(result)
    }
}

impl ToTokens for Actions {
    fn to_tokens(&self, tokens: &mut proc_macro2::TokenStream) {
        let bits = syn::LitInt::new(&self.data.bits.to_string(), Span::call_site());
        let terminal_bits =
            syn::LitInt::new(&self.terminal_actions.bits.to_string(), Span::call_site());
        tokens.extend(quote! {
        Actions { data: ActionData::from(#bits),
                  terminal_actions: ActionData::from(#terminal_bits) } });
    }
}

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
        let frame_mask = ActionData::PacketTrack | ActionData::UpdatePDU;
        actions.data |= frame_mask;
        assert!(actions.data.contains(frame_mask));
        actions.clear_mask(frame_mask);

        // Clear an action (or set of actions), including some that aren't set
        actions.clear_mask(ActionData::PacketContinue | ActionData::SessionFilter);

        // Check that no actions are requested
        assert!(actions.drop());

        actions.data |= ActionData::ProtoProbe | ActionData::ProtoFilter;
        assert!(actions.parse_any());

        // Check from usize: 2 LSBs set
        let mask: usize = 3;
        let action_data = ActionData::from(mask);
        assert!(
            action_data.contains(ActionData::PacketContinue)
                && action_data.contains(ActionData::PacketDeliver)
        );
    }
}
