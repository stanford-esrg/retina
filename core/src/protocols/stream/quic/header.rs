//! Quic header types

use serde::Serialize;

/// Quic Long Header
#[derive(Debug, Serialize)]
pub struct QuicLongHeader {
    pub packet_type: u8,
    pub type_specific: u8,
    pub version: u32,
    pub dcid_len: u8, // length of dcid in bytes
    pub dcid: String, // hex string
    pub scid_len: u8, // length of scid in bytes
    pub scid: String, // hex string
}

/// Quic Short Header
#[derive(Debug, Serialize)]
pub struct QuicShortHeader {
    pub dcid: Option<String>, // optional. If not pre-existing cid then none.

    #[serde(skip)]
    pub dcid_bytes: Vec<u8>,
}
