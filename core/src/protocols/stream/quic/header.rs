//! Quic header types

use serde::Serialize;

use crate::protocols::stream::quic::parser::QuicError;

/// Quic Long Header
#[derive(Debug, Serialize, Clone)]
pub struct QuicLongHeader {
    pub packet_type: LongHeaderPacketType,
    pub type_specific: u8,
    pub version: u32,
    pub dcid_len: u8,              // length of dcid in bytes
    pub dcid: String,              // hex string
    pub scid_len: u8,              // length of scid in bytes
    pub scid: String,              // hex string
    pub token_len: Option<u64>,    // length of token in bytes, if packet is of type Init or Retry
    pub token: Option<String>,     // hex string, if packet is of type Init or Retry
    pub retry_tag: Option<String>, // hex string, if packet is of type Retry
}

/// Quic Short Header
#[derive(Debug, Serialize, Clone)]
pub struct QuicShortHeader {
    pub dcid: Option<String>, // optional. If not pre-existing cid then none.

    #[serde(skip)]
    pub dcid_bytes: Vec<u8>,
}

// Long Header Packet Types from RFC 9000 Table 5
#[derive(Debug, Clone, Serialize, Copy)]
pub enum LongHeaderPacketType {
    Initial,
    ZeroRTT,
    Handshake,
    Retry,
}

impl LongHeaderPacketType {
    pub fn from_u8(value: u8) -> Result<LongHeaderPacketType, QuicError> {
        match value {
            0x00 => Ok(LongHeaderPacketType::Initial),
            0x01 => Ok(LongHeaderPacketType::ZeroRTT),
            0x02 => Ok(LongHeaderPacketType::Handshake),
            0x03 => Ok(LongHeaderPacketType::Retry),
            _ => Err(QuicError::UnknowLongHeaderPacketType),
        }
    }
}
