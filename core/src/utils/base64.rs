//! Helper functions for Base64 encoding and decoding.

use serde::{Deserialize, Serialize};
use serde::{Deserializer, Serializer};

/// Encodes byte slice as a Base64 string.
pub fn serialize<S: Serializer>(v: &[u8], s: S) -> Result<S::Ok, S::Error> {
    let base64 = base64::encode(v);
    String::serialize(&base64, s)
}

/// Decodes Base64 string as a byte vector.
pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
    let base64 = String::deserialize(d)?;
    base64::decode(base64.as_bytes()).map_err(serde::de::Error::custom)
}
