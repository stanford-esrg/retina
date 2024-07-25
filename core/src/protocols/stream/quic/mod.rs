//! QUIC protocol parser.
//!
//! ## Remarks
//! [QUIC-INVARIANTS] https://datatracker.ietf.org/doc/rfc8999/
//! [QUIC-RFC9000] https://datatracker.ietf.org/doc/rfc9000/ (Quic V1)
//! Retina currently only parses Quic Long and Short Headers and does not attempt to parse TLS or HTTP/3 out of
//! Quic packets. The Quic protocol parser makes several assumptions about the way that quic
//! packets will behave:
//! - Assume that the Quic version is one as listed in the QuicVersion Enum in the quic/parser.rs file
//! - Assume that the dcid of a short header is a maximum of 20 bytes.
//! - Assume that the packet will not try to grease the fixed bit.
//!   [QUIC-GREASE](https://www.rfc-editor.org/rfc/rfc9287.html)
//!
//! Additionally, there are a couple decisions made in the design of the quic parser:
//! - The parser will not parse a short header dcid if it is not a part of a pre-identified connection
//! - The payload bytes count is a lazy counter which does not try to exclude tokens for encryption,
//!   which is a process that happens in wireshark.
/*
TODO: support parsing the tls out of the initial quic packet setup
TODO support dns over quic
TODO: support HTTP/3
*/
pub(crate) mod parser;

use std::collections::HashSet;

pub use self::header::{QuicLongHeader, QuicShortHeader};
use crypto::Open;
use frame::QuicFrame;
use header::LongHeaderPacketType;
use serde::Serialize;

use super::tls::Tls;
pub(crate) mod crypto;
pub(crate) mod frame;
pub(crate) mod header;

/// Errors Thrown throughout QUIC parsing. These are handled by retina and used to skip packets.
#[derive(Debug)]
pub enum QuicError {
    FixedBitNotSet,
    PacketTooShort,
    UnknownVersion,
    ShortHeader,
    UnknowLongHeaderPacketType,
    NoLongHeader,
    UnsupportedVarLen,
    InvalidDataIndices,
    CryptoFail,
    FailedHeaderProtection,
    UnknownFrameType,
    TlsParseFail,
    MissingCryptoFrames,
}

/// Parsed Quic Packet contents
#[derive(Debug, Serialize)]
pub struct QuicConn {
    pub packets: Vec<QuicPacket>,
    pub cids: HashSet<String>,
    pub tls: Tls,
    pub client_opener: Option<Open>,
    pub server_opener: Option<Open>,
    #[serde(skip_serializing)]
    pub client_buffer: Vec<u8>,
    #[serde(skip_serializing)]
    pub server_buffer: Vec<u8>,
}

/// Parsed Quic Packet contents
#[derive(Debug, Serialize)]
pub struct QuicPacket {
    /// Quic Short header
    pub short_header: Option<QuicShortHeader>,

    /// Quic Long header
    pub long_header: Option<QuicLongHeader>,

    /// The number of bytes contained in the estimated payload
    pub payload_bytes_count: Option<u64>,

    pub frames: Option<Vec<QuicFrame>>,
}

impl QuicPacket {
    /// Returns the header type of the Quic packet (ie. "long" or "short")
    pub fn header_type(&self) -> &str {
        match &self.long_header {
            Some(_) => "long",
            None => match &self.short_header {
                Some(_) => "short",
                None => "",
            },
        }
    }

    /// Returns the packet type of the Quic packet
    pub fn packet_type(&self) -> Result<LongHeaderPacketType, QuicError> {
        match &self.long_header {
            Some(long_header) => Ok(long_header.packet_type),
            None => Err(QuicError::NoLongHeader),
        }
    }

    /// Returns the version of the Quic packet
    pub fn version(&self) -> u32 {
        match &self.long_header {
            Some(long_header) => long_header.version,
            None => 0,
        }
    }

    /// Returns the destination connection ID of the Quic packet or an empty string if it does not exist
    pub fn dcid(&self) -> &str {
        match &self.long_header {
            Some(long_header) => {
                if long_header.dcid_len > 0 {
                    &long_header.dcid
                } else {
                    ""
                }
            }
            None => {
                if let Some(short_header) = &self.short_header {
                    short_header.dcid.as_deref().unwrap_or("")
                } else {
                    ""
                }
            }
        }
    }

    /// Returns the source connection ID of the Quic packet or an empty string if it does not exist
    pub fn scid(&self) -> &str {
        match &self.long_header {
            Some(long_header) => {
                if long_header.scid_len > 0 {
                    &long_header.scid
                } else {
                    ""
                }
            }
            None => "",
        }
    }

    /// Returns the number of bytes in the payload of the Quic packet
    pub fn payload_bytes_count(&self) -> u64 {
        if let Some(count) = self.payload_bytes_count {
            count
        } else {
            0
        }
    }
}
