//! Quic Header parser
//! Custom Quic Parser with many design choices borrowed from
//! [Wireshark Quic Disector](https://gitlab.com/wireshark/wireshark/-/blob/master/epan/dissectors/packet-quic.c)
//!
use crate::protocols::stream::quic::header::{
    LongHeaderPacketType, QuicLongHeader, QuicShortHeader,
};
use crate::protocols::stream::quic::QuicPacket;
use crate::protocols::stream::{
    SessionState, ConnParsable, L4Pdu, ParseResult, ProbeResult, Session, SessionData,
};
use std::collections::HashMap;

#[derive(Default, Debug)]
pub struct QuicParser {
    /// Maps session ID to Quic transaction
    sessions: HashMap<usize, QuicPacket>,
    /// Total sessions ever seen (Running session ID)
    cnt: usize,
}

impl ConnParsable for QuicParser {
    fn parse(&mut self, pdu: &L4Pdu) -> ParseResult {
        let offset = pdu.offset();
        let length = pdu.length();
        if length == 0 {
            return ParseResult::Skipped;
        }

        if let Ok(data) = (pdu.mbuf_ref()).get_data_slice(offset, length) {
            self.process(data)
        } else {
            log::warn!("Malformed packet on parse");
            ParseResult::Skipped
        }
    }

    fn probe(&self, pdu: &L4Pdu) -> ProbeResult {
        if pdu.length() < 5 {
            return ProbeResult::Unsure;
        }

        let offset = pdu.offset();
        let length = pdu.length();

        if let Ok(data) = (pdu.mbuf).get_data_slice(offset, length) {
            // Check if Fixed Bit is set
            if (data[0] & 0x40) == 0 {
                return ProbeResult::NotForUs;
            }

            if (data[0] & 0x80) != 0 {
                // Potential Long Header
                if data.len() < 6 {
                    return ProbeResult::Unsure;
                }

                // Check if version is known
                let version = ((data[1] as u32) << 24)
                    | ((data[2] as u32) << 16)
                    | ((data[3] as u32) << 8)
                    | (data[4] as u32);
                match QuicVersion::from_u32(version) {
                    QuicVersion::Unknown => ProbeResult::NotForUs,
                    _ => ProbeResult::Certain,
                }
            } else {
                ProbeResult::Unsure
            }
        } else {
            log::warn!("Malformed packet");
            ProbeResult::Error
        }
    }

    fn remove_session(&mut self, session_id: usize) -> Option<Session> {
        self.sessions.remove(&session_id).map(|quic| Session {
            data: SessionData::Quic(Box::new(quic)),
            id: session_id,
        })
    }

    fn drain_sessions(&mut self) -> Vec<Session> {
        self.sessions
            .drain()
            .map(|(session_id, quic)| Session {
                data: SessionData::Quic(Box::new(quic)),
                id: session_id,
            })
            .collect()
    }

    fn session_parsed_state(&self) -> SessionState {
        SessionState::Parsing
    }
}

/// Supported Quic Versions
#[derive(Debug, PartialEq, Eq, Hash)]
enum QuicVersion {
    ReservedNegotiation = 0x00000000,
    Rfc9000 = 0x00000001, // Quic V1
    Rfc9369 = 0x6b3343cf, // Quic V2
    Unknown,
}

impl QuicVersion {
    fn from_u32(version: u32) -> Self {
        match version {
            0x00000000 => QuicVersion::ReservedNegotiation,
            0x00000001 => QuicVersion::Rfc9000,
            0x6b3343cf => QuicVersion::Rfc9369,
            _ => QuicVersion::Unknown,
        }
    }
}

/// Errors Thrown by Quic Parser. These are handled by retina and used to skip packets.
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
}

impl QuicPacket {
    /// Processes the connection ID bytes array to a hex string
    pub fn vec_u8_to_hex_string(vec: &[u8]) -> String {
        vec.iter()
            .map(|&byte| format!("{:02x}", byte))
            .collect::<Vec<String>>()
            .join("")
    }

    // Calculate the length of a variable length encoding
    // See RFC 9000 Section 16 for details
    pub fn get_var_len(a: u8) -> Result<usize, QuicError> {
        let two_msb = a >> 6;
        match two_msb {
            0b00 => Ok(1),
            0b01 => Ok(2),
            0b10 => Ok(4),
            0b11 => Ok(8),
            _ => Err(QuicError::UnsupportedVarLen),
        }
    }

    // Masks variable length encoding and returns u64 value for remainder of field
    fn slice_to_u64(data: &[u8]) -> Result<u64, QuicError> {
        if data.len() > 8 {
            return Err(QuicError::UnsupportedVarLen);
        }

        let mut result: u64 = 0;
        for &byte in data {
            result = (result << 8) | u64::from(byte);
        }
        result &= !(0b11 << ((data.len() * 8) - 2)); // Var length encoding mask
        Ok(result)
    }

    fn access_data(data: &[u8], start: usize, end: usize) -> Result<&[u8], QuicError> {
        if end < start {
            return Err(QuicError::InvalidDataIndices);
        }
        if data.len() < end {
            return Err(QuicError::PacketTooShort);
        }
        Ok(&data[start..end])
    }

    /// Parses Quic packet from bytes
    pub fn parse_from(data: &[u8]) -> Result<QuicPacket, QuicError> {
        let mut offset = 0;
        let packet_header_byte = QuicPacket::access_data(data, offset, offset + 1)?[0];
        offset += 1;
        // Check the fixed bit
        if (packet_header_byte & 0x40) == 0 {
            return Err(QuicError::FixedBitNotSet);
        }
        // Check the Header form
        if (packet_header_byte & 0x80) != 0 {
            // Long Header
            // Parse packet type
            let packet_type = LongHeaderPacketType::from_u8((packet_header_byte & 0x30) >> 4)?;
            let type_specific = packet_header_byte & 0x0F; // Remainder of information from header byte, Reserved and protected packet number length
                                                           // Parse version
            let version_bytes = QuicPacket::access_data(data, offset, offset + 4)?;
            let version = ((version_bytes[0] as u32) << 24)
                | ((version_bytes[1] as u32) << 16)
                | ((version_bytes[2] as u32) << 8)
                | (version_bytes[3] as u32);
            if QuicVersion::from_u32(version) == QuicVersion::Unknown {
                return Err(QuicError::UnknownVersion);
            }
            offset += 4;
            // Parse DCID
            let dcid_len = QuicPacket::access_data(data, offset, offset + 1)?[0];
            offset += 1;
            let dcid_bytes = QuicPacket::access_data(data, offset, offset + dcid_len as usize)?;
            let dcid = QuicPacket::vec_u8_to_hex_string(dcid_bytes);
            offset += dcid_len as usize;
            // Parse SCID
            let scid_len = QuicPacket::access_data(data, offset, offset + 1)?[0];
            offset += 1;
            let scid_bytes = QuicPacket::access_data(data, offset, offset + scid_len as usize)?;
            let scid = QuicPacket::vec_u8_to_hex_string(scid_bytes);
            offset += scid_len as usize;

            let token_len;
            let token;
            let packet_len;
            let retry_tag;
            // Parse packet type specific fields
            match packet_type {
                LongHeaderPacketType::Initial => {
                    retry_tag = None;
                    // Parse token
                    let token_len_len = QuicPacket::get_var_len(
                        QuicPacket::access_data(data, offset, offset + 1)?[0],
                    )?;
                    token_len = Some(QuicPacket::slice_to_u64(QuicPacket::access_data(
                        data,
                        offset,
                        offset + token_len_len,
                    )?)?);
                    offset += token_len_len;
                    let token_bytes = QuicPacket::access_data(
                        data,
                        offset,
                        offset + token_len.unwrap() as usize,
                    )?;
                    token = Some(QuicPacket::vec_u8_to_hex_string(token_bytes));
                    offset += token_len.unwrap() as usize;
                    // Parse payload length
                    let packet_len_len = QuicPacket::get_var_len(
                        QuicPacket::access_data(data, offset, offset + 1)?[0],
                    )?;
                    packet_len = Some(QuicPacket::slice_to_u64(QuicPacket::access_data(
                        data,
                        offset,
                        offset + packet_len_len,
                    )?)?);
                }
                LongHeaderPacketType::ZeroRTT | LongHeaderPacketType::Handshake => {
                    token_len = None;
                    token = None;
                    retry_tag = None;
                    // Parse payload length
                    let packet_len_len = QuicPacket::get_var_len(
                        QuicPacket::access_data(data, offset, offset + 1)?[0],
                    )?;
                    packet_len = Some(QuicPacket::slice_to_u64(QuicPacket::access_data(
                        data,
                        offset,
                        offset + packet_len_len,
                    )?)?);
                }
                LongHeaderPacketType::Retry => {
                    packet_len = None;
                    token_len = Some((data.len() - offset - 16) as u64);
                    // Parse retry token
                    let token_bytes = QuicPacket::access_data(
                        data,
                        offset,
                        offset + token_len.unwrap() as usize,
                    )?;
                    token = Some(QuicPacket::vec_u8_to_hex_string(token_bytes));
                    offset += token_len.unwrap() as usize;
                    // Parse retry tag
                    let retry_tag_bytes = QuicPacket::access_data(data, offset, offset + 16)?;
                    retry_tag = Some(QuicPacket::vec_u8_to_hex_string(retry_tag_bytes));
                }
            }

            Ok(QuicPacket {
                payload_bytes_count: packet_len,
                short_header: None,
                long_header: Some(QuicLongHeader {
                    packet_type,
                    type_specific,
                    version,
                    dcid_len,
                    dcid,
                    scid_len,
                    scid,
                    token_len,
                    token,
                    retry_tag,
                }),
            })
        } else {
            // Short Header
            let mut max_dcid_len = 20;
            if data.len() < 1 + max_dcid_len {
                max_dcid_len = data.len() - 1;
            }
            // Parse DCID
            let dcid_bytes = QuicPacket::access_data(data, offset, offset + max_dcid_len)?.to_vec();
            offset += max_dcid_len;
            // Counts all bytes remaining
            let payload_bytes_count = Some((data.len() - offset) as u64);
            Ok(QuicPacket {
                short_header: Some(QuicShortHeader {
                    dcid: None,
                    dcid_bytes,
                }),
                long_header: None,
                payload_bytes_count,
            })
        }
    }
}

impl QuicParser {
    fn process(&mut self, data: &[u8]) -> ParseResult {
        if let Ok(quic) = QuicPacket::parse_from(data) {
            let session_id = self.cnt;
            self.sessions.insert(session_id, quic);
            self.cnt += 1;
            ParseResult::Done(session_id)
        } else {
            ParseResult::Skipped
        }
    }
}
