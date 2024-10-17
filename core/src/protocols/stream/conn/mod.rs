/// Types for parsing FiveTuple data from a Conn struct.
/// This is used by retina-filtergen if a packet-level field must be checked when the raw
/// packet is not available, but connection data is.
pub mod layer3;
pub mod layer4;

pub use layer3::{Ipv4CData, Ipv6CData};
pub use layer4::{TcpCData, UdpCData};

use crate::protocols::stream::ConnData;
use anyhow::Result;
use thiserror::Error;

#[derive(Error, Debug)]
pub(crate) enum ConnDataError {
    #[error("Invalid protocol")]
    InvalidProtocol,
}

/// A trait that all extractable ConnData fields must implement
pub trait ConnField {
    /// Parse from the ConnData
    fn parse_from(conn: &ConnData) -> Result<Self>
    where
        Self: Sized;

    /// Supported methods, as strings (e.g., src_port, dst_addr...)
    /// This allows for better error-checking at compile-time
    fn supported_fields() -> Vec<&'static str>;
}
