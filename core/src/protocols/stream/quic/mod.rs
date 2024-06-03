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

pub use self::header::{QuicLongHeader, QuicShortHeader};
use serde::Serialize;
mod header;

/// Parsed Quic Packet contents
#[derive(Debug, Serialize)]
pub struct Quic {
    /// Quic Short header
    pub short_header: Option<QuicShortHeader>,

    /// Quic Long header
    pub long_header: Option<QuicLongHeader>,

    /// The number of bytes contained in the estimated payload
    pub payload_bytes_count: u16,
}

impl Quic {
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
    pub fn packet_type(&self) -> u8 {
        match &self.long_header {
            Some(long_header) => long_header.packet_type,
            None => 0,
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
    pub fn dcid(&self) -> String {
        match &self.long_header {
            Some(long_header) => {
                if long_header.dcid_len > 0 {
                    long_header.dcid.clone()
                } else {
                    String::new()
                }
            }
            None => {
                if let Some(short_header) = &self.short_header {
                    match &short_header.dcid {
                        Some(dcid) => dcid.clone(),
                        None => String::new(),
                    }
                } else {
                    String::new()
                }
            }
        }
    }

    /// Returns the source connection ID of the Quic packet or an empty string if it does not exist
    pub fn scid(&self) -> String {
        match &self.long_header {
            Some(long_header) => {
                if long_header.scid_len > 0 {
                    long_header.scid.clone()
                } else {
                    String::new()
                }
            }
            None => String::new(),
        }
    }

    /// Returns the number of bytes in the payload of the Quic packet
    pub fn payload_bytes_count(&self) -> u16 {
        self.payload_bytes_count
    }
}
