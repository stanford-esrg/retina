/// The abstraction level of a subscribable type
/// Used at compile-time to determine actions
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Level {
    /// User has requested packets.
    /// If packet-level filter, matched data delivered at packet filter.
    /// Else, packets are buffered until higher-level filter match.
    Packet, 
    /// User has requested all connection data
    /// - Connection will be tracked until termination
    Connection,
    /// User has requested session data
    /// - Sessions will be parsed and delivered
    Session
}