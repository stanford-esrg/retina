//! For each connection, the Retina framework applies multiple filtering stages as
//! packets are received in order to determine (1) whether packets from that connection
//! should continue to be processed and (2) what to do with these packets.
//!
//! Each connection is associated with a set of Actions. These actions specify the
//! operations the framework will perform for the connection *now or in the future*:
//! e.g., probe for the application-layer protocol (until it is identified), deliver
//! the connection (when it has terminated), deliver all subsequent packets in the
//! connection, etc. An empty Actions struct will cause the connection to be dropped.
//!
//! Each filter stage returns a set of actions and a set of terminal actions.
//! The terminal actions are the subset of actions that are maintained through
//! the next filter stage.
use bitmask_enum::bitmask;
use std::fmt;

#[bitmask]
#[bitmask_config(vec_debug)]
pub enum ActionData {
    /// Forward new packet to connection tracker
    /// Should only be used in the PacketContinue filter
    PacketContinue,

    /// Deliver future packet data (via the PacketDelivery filter) in this connection to a callback
    /// TCP packets are delivered with the following specifications:
    /// - Packet-level filters (can match at packet stage): in the order received (pre-reassembly)
    /// - All other filters: post-reassembly
    PacketDeliver,

    /// Store packets in this connection in tracked data for
    /// potential future delivery. Used on a non-terminal match
    /// for a packet-level datatype.
    PacketCache,
    /// Store packets in this connection in tracked data for a
    /// datatype that requires tracking and delivering packets.
    PacketTrack,

    /// Probe for (identify) the application-layer protocol
    ProtoProbe,
    /// Once the application-layer protocl is identified, apply the ProtocolFilter.
    ProtoFilter,

    /// Once the application-layer session has been parsed, apply the SessionFilter
    SessionFilter,
    /// Once the application-layer session has been parsed, deliver it (by applying
    /// the SessionFilter).
    SessionDeliver,
    /// Once the application-layer session has been parsed, store it in tracked data.
    SessionTrack,

    /// The subscribable type "update" methods should be invoked (for TCP: pre-reassembly)
    UpdatePDU,

    /// The subscribable type "update" methods should be invoked post-reassembly (TCP only)
    Reassemble,

    /// Deliver connection data (via the ConnectionDelivery filter) when it terminates
    ConnDeliver,

    /// Invoke any active streaming callbacks.
    Stream,
}

/// Actions maintained per-connection
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct Actions {
    /// All actions (terminal and non-terminal) that should
    /// be performed following the application of a filter.
    pub data: ActionData,
    /// All actions that should continue to be performed
    /// regardless of what the next filter returns
    /// E.g., if a terminal match for a connection-level filter
    /// occurs at the packet layer, we should continue tracking
    /// the connection regardless of later filter results.
    pub terminal_actions: ActionData,
}

impl Default for Actions {
    fn default() -> Self {
        Self::new()
    }
}

impl Actions {
    // Create an empty Actions bitmask
    pub fn new() -> Self {
        Self {
            data: ActionData::none(),
            terminal_actions: ActionData::none(),
        }
    }

    // Store the result of a new filter
    // Used at runtime after application of next filter
    #[inline]
    pub fn update(&mut self, actions: &Actions) {
        self.data = self.terminal_actions | actions.data;
        self.terminal_actions |= actions.terminal_actions;
    }

    // Combine terminal and non-terminal actions
    // Used for building a filter tree at compile time and when
    // applying a filter at runtime if additional conditions are met.
    #[inline]
    pub fn push(&mut self, actions: &Actions) {
        self.data |= actions.data;
        self.terminal_actions |= actions.terminal_actions;
    }

    // Returns true if no actions are set (i.e., the connection can
    // be dropped by the framework).
    #[inline]
    pub fn drop(&self) -> bool {
        self.data.is_none() && self.terminal_actions.is_none()
    }

    // Update `self` to contain only actions not in `actions`
    #[inline]
    pub(crate) fn clear_intersection(&mut self, actions: &Actions) {
        self.data &= actions.data.not();
        self.terminal_actions &= actions.data.not();
    }

    // Conn tracker must deliver each PDU to tracked data when received
    #[inline]
    pub(crate) fn update_pdu(&self) -> bool {
        self.data.intersects(ActionData::UpdatePDU)
    }

    /// True if the connection needs to be reassembled
    pub(crate) fn reassemble(&self) -> bool {
        self.data.intersects(ActionData::Reassemble) || self.parse_any()
    }

    /// True if streaming callbacks are available to be invoked
    pub(crate) fn stream_deliver(&self) -> bool {
        self.data.intersects(ActionData::Stream)
    }

    /// True if the framework should buffer mbufs for this connection,
    /// either for future delivery (Cache) or for a datatype that requires
    /// tracking packets.
    #[inline]
    pub(crate) fn buffer_packet(&self, reassembled: bool) -> bool {
        match reassembled {
            true => self.data.intersects(ActionData::PacketTrack),
            false => self
                .data
                .intersects(ActionData::PacketTrack | ActionData::PacketCache),
        }
    }

    #[inline]
    pub(crate) fn cache_packet(&self) -> bool {
        self.data.intersects(ActionData::PacketCache)
    }

    // True if application-layer probing or parsing should be applied
    #[inline]
    pub(crate) fn parse_any(&self) -> bool {
        self.data.intersects(
            ActionData::ProtoProbe
                | ActionData::ProtoFilter
                | ActionData::SessionFilter
                | ActionData::SessionDeliver
                | ActionData::SessionTrack,
        )
    }

    /// True if nothing except delivery is required
    /// Allows delivering and dropping the connection to happen early
    #[inline]
    pub(crate) fn conn_deliver_only(&self) -> bool {
        self.data == ActionData::ConnDeliver
    }

    // True if the session filter should be applied
    #[inline]
    pub(crate) fn apply_session_filter(&mut self) -> bool {
        // \note deliver filter is in session filter
        self.data
            .intersects(ActionData::SessionFilter | ActionData::SessionDeliver)
    }

    // True if the protocol filter should be applied
    #[inline]
    pub(crate) fn apply_proto_filter(&mut self) -> bool {
        self.data.contains(ActionData::ProtoFilter)
    }

    // True if the framework should probe for the app-layer protocol
    #[inline]
    pub(crate) fn session_probe(&self) -> bool {
        self.data
            .intersects(ActionData::ProtoProbe | ActionData::ProtoFilter)
    }

    // True if the framework should parse application-layer data
    #[inline]
    pub(crate) fn session_parse(&self) -> bool {
        self.data.intersects(
            ActionData::SessionDeliver | ActionData::SessionFilter | ActionData::SessionTrack,
        ) && !self.session_probe() // still at probing stage
    }

    // True if the framework should buffer parsed sessions
    #[inline]
    pub(crate) fn session_track(&self) -> bool {
        self.data.intersects(ActionData::SessionTrack)
    }

    // True if the framework should deliver future packets in this connection
    #[inline]
    pub(crate) fn packet_deliver(&self) -> bool {
        self.data.intersects(ActionData::PacketDeliver)
    }

    // After parsing a session, the framework must decide whether to continue
    // probing for sessions depending on the protocol
    // If no further parsing is required (e.g., TLS Handshake), this method
    // should be invoked.
    #[inline]
    pub(crate) fn session_clear_parse(&mut self) {
        self.clear_mask(
            ActionData::SessionFilter
                | ActionData::SessionDeliver
                | ActionData::SessionTrack
                | ActionData::ProtoProbe,
        );
    }

    // Subscription requires protocol probe/parse but matched at packet stage
    // Update action to reflect state transition to protocol parsing
    #[inline]
    pub(crate) fn session_done_probe(&mut self) {
        if self.terminal_actions.contains(ActionData::ProtoProbe) {
            // Maintain in terminal actions, but move to parse stage
            self.data &= (ActionData::ProtoProbe).not();
            assert!(self
                .data
                .intersects(ActionData::SessionDeliver | ActionData::SessionTrack));
        }
    }

    // Some app-layer protocols revert to probing after session is parsed
    // This is done if more sessions are expected
    pub(crate) fn session_set_probe(&mut self) {
        // If protocol probing was set at the PacketFilter stage (i.e.,
        // terminal match for a subscription that requires parsing sessions),
        // then the ProtoProbe action will be "terminal"
        if self.terminal_actions.contains(ActionData::ProtoProbe) {
            // Clear out session actions set by session_filter or protocol_filter
            self.data &=
                (ActionData::SessionFilter | ActionData::SessionDeliver | ActionData::SessionTrack)
                    .not();

            // While maintiaining those set by packet filter
            self.data |= self.terminal_actions;
        }

        // Return to probing stage
        self.data |= ActionData::ProtoProbe | ActionData::ProtoFilter;

        /*
         * Note: it could be inefficient to re-apply the proto filter
         *       (protocol was already ID'd). However, this makes it easier
         *       to ensure that correct actions are (re-)populated
         *       protocol filter if we already know the protocol.
         *       This also allows for extensibility to nested protocols.
         */
    }

    // True if the connection should be delivered at termination
    #[inline]
    pub(crate) fn connection_matched(&self) -> bool {
        self.terminal_actions.intersects(ActionData::ConnDeliver)
    }

    // Clear all actions
    #[inline]
    pub(crate) fn clear(&mut self) {
        self.terminal_actions = ActionData::none();
        self.data = ActionData::none();
    }

    // Clear a subset of actions
    #[inline]
    pub(crate) fn clear_mask(&mut self, mask: ActionData) {
        self.data &= mask.not();
        self.terminal_actions &= mask.not();
    }
}

use proc_macro2::{Ident, Span};
use quote::{quote, ToTokens};
use std::str::FromStr;

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
            "Reassemble" => Ok(ActionData::Reassemble),
            "PacketTrack" => Ok(ActionData::PacketTrack),
            "PacketCache" => Ok(ActionData::PacketCache),
            "ConnDeliver" => Ok(ActionData::ConnDeliver),
            _ => Result::Err(core::fmt::Error),
        }
    }
}

impl fmt::Display for ActionData {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let s = match *self {
            ActionData::PacketContinue => "PacketContinue",
            ActionData::PacketDeliver => "PacketDeliver",
            ActionData::ProtoProbe => "ProtoProbe",
            ActionData::ProtoFilter => "ProtoFilter",
            ActionData::SessionFilter => "SessionFilter",
            ActionData::SessionDeliver => "SessionDeliver",
            ActionData::SessionTrack => "SessionTrack",
            ActionData::UpdatePDU => "UpdatePDU",
            ActionData::Reassemble => "Reassemble",
            ActionData::PacketTrack => "PacketTrack",
            ActionData::PacketCache => "PacketCache",
            ActionData::ConnDeliver => "ConnDeliver",
            _ => panic!("Unknown ActionData"),
        };
        write!(f, "{}", s)
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
