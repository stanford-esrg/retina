//! Quic Header parser
//! Custom Quic Parser with many design choices borrowed from
//! [Wireshark Quic Disector](https://gitlab.com/wireshark/wireshark/-/blob/master/epan/dissectors/packet-quic.c)
//!
use crate::protocols::stream::quic::crypto::calc_init_keys;
use crate::protocols::stream::quic::frame::QuicFrame;
use crate::protocols::stream::quic::header::{
    LongHeaderPacketType, QuicLongHeader, QuicShortHeader,
};
use crate::protocols::stream::quic::{QuicError, QuicPacket};
use crate::protocols::stream::tls::Tls;
use crate::protocols::stream::{
    ConnParsable, ConnState, L4Pdu, ParseResult, ProbeResult, Session, SessionData,
};
use byteorder::{BigEndian, ByteOrder};
use std::collections::HashSet;
use tls_parser::parse_tls_message_handshake;

use super::QuicConn;

#[derive(Debug)]
pub struct QuicParser {
    // /// Maps session ID to Quic transaction
    // sessions: HashMap<usize, QuicPacket>,
    // /// Total sessions ever seen (Running session ID)
    // cnt: usize,
    sessions: Vec<QuicConn>,
}

impl Default for QuicParser {
    fn default() -> Self {
        QuicParser {
            sessions: vec![QuicConn::new()],
        }
    }
}

impl ConnParsable for QuicParser {
    fn parse(&mut self, pdu: &L4Pdu) -> ParseResult {
        let offset = pdu.offset();
        let length = pdu.length();
        if length == 0 {
            return ParseResult::Skipped;
        }

        if let Ok(data) = (pdu.mbuf_ref()).get_data_slice(offset, length) {
            self.sessions[0].parse_packet(data, pdu.dir)
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
        self.sessions.pop().map(|quic| Session {
            data: SessionData::Quic(Box::new(quic)),
            id: session_id,
        })
    }

    fn drain_sessions(&mut self) -> Vec<Session> {
        self.sessions
            .drain(..)
            .map(|quic| Session {
                data: SessionData::Quic(Box::new(quic)),
                id: 0,
            })
            .collect()
    }

    fn session_match_state(&self) -> ConnState {
        ConnState::Parsing
    }
    fn session_nomatch_state(&self) -> ConnState {
        ConnState::Parsing
    }
}

/// Supported Quic Versions
#[derive(Debug, PartialEq, Eq, Hash)]
#[repr(u32)]
pub enum QuicVersion {
    ReservedNegotiation = 0x00000000,
    Rfc9000 = 0x00000001, // Quic V1
    Rfc9369 = 0x6b3343cf, // Quic V2
    Draft27 = 0xff00001b, // Quic draft 27
    Draft28 = 0xff00001c, // Quic draft 28
    Draft29 = 0xff00001d, // Quic draft 29
    Mvfst27 = 0xfaceb002, // Facebook Implementation of draft 27
    Unknown,
}

impl QuicVersion {
    pub fn from_u32(version: u32) -> Self {
        match version {
            0x00000000 => QuicVersion::ReservedNegotiation,
            0x00000001 => QuicVersion::Rfc9000,
            0x6b3343cf => QuicVersion::Rfc9369,
            0xff00001b => QuicVersion::Draft27,
            0xff00001c => QuicVersion::Draft28,
            0xff00001d => QuicVersion::Draft29,
            0xfaceb002 => QuicVersion::Mvfst27,
            _ => QuicVersion::Unknown,
        }
    }
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
    pub fn slice_to_u64(data: &[u8]) -> Result<u64, QuicError> {
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

    pub fn access_data(data: &[u8], start: usize, end: usize) -> Result<&[u8], QuicError> {
        if end < start {
            return Err(QuicError::InvalidDataIndices);
        }
        if data.len() < end {
            return Err(QuicError::PacketTooShort);
        }
        Ok(&data[start..end])
    }

    /// Parses Quic packet from bytes
    pub fn parse_from(
        conn: &mut QuicConn,
        data: &[u8],
        mut offset: usize,
        dir: bool,
    ) -> Result<(QuicPacket, usize), QuicError> {
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
            if dcid_len > 0 && !conn.cids.contains(&dcid) {
                conn.cids.insert(dcid.clone());
            }
            offset += dcid_len as usize;
            // Parse SCID
            let scid_len = QuicPacket::access_data(data, offset, offset + 1)?[0];
            offset += 1;
            let scid_bytes = QuicPacket::access_data(data, offset, offset + scid_len as usize)?;
            let scid = QuicPacket::vec_u8_to_hex_string(scid_bytes);
            if scid_len > 0 && !conn.cids.contains(&scid) {
                conn.cids.insert(scid.clone());
            }
            offset += scid_len as usize;

            let token_len;
            let token;
            let packet_len;
            let retry_tag;
            let decrypted_payload;
            // Parse packet type specific fields
            match packet_type {
                LongHeaderPacketType::Initial => {
                    retry_tag = None;
                    // Parse token
                    let token_len_len = QuicPacket::get_var_len(
                        QuicPacket::access_data(data, offset, offset + 1)?[0],
                    )?;
                    let token_len_bytes =
                        QuicPacket::access_data(data, offset, offset + token_len_len)?;
                    token_len = Some(QuicPacket::slice_to_u64(token_len_bytes)?);
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
                    let packet_len_bytes =
                        QuicPacket::access_data(data, offset, offset + packet_len_len)?;
                    packet_len = Some(QuicPacket::slice_to_u64(packet_len_bytes)?);
                    offset += packet_len_len;
                    if conn.client_opener.is_none() {
                        // Derive initial keys
                        let [client_opener, server_opener] = calc_init_keys(dcid_bytes, version)?;
                        conn.client_opener = Some(client_opener);
                        conn.server_opener = Some(server_opener);
                    }
                    // Calculate HP
                    let sample_len = conn.client_opener.as_ref().unwrap().sample_len();
                    let hp_sample =
                        QuicPacket::access_data(data, offset + 4, offset + 4 + sample_len)?;
                    let mask = if dir {
                        conn.client_opener.as_ref().unwrap().new_mask(hp_sample)?
                    } else {
                        conn.server_opener.as_ref().unwrap().new_mask(hp_sample)?
                    };
                    // Remove HP from packet header byte
                    let unprotected_header = packet_header_byte ^ (mask[0] & 0b00001111);
                    if (unprotected_header >> 2) & 0b00000011 != 0 {
                        return Err(QuicError::FailedHeaderProtection);
                    }
                    // Parse packet number
                    let packet_num_len = ((unprotected_header & 0b00000011) + 1) as usize;
                    let packet_number_bytes =
                        QuicPacket::access_data(data, offset, offset + packet_num_len)?;
                    let mut packet_number = vec![0; 4 - packet_num_len];
                    for i in 0..packet_num_len {
                        packet_number.push(packet_number_bytes[i] ^ mask[i + 1]);
                    }

                    let initial_packet_number_bytes = &packet_number[4 - packet_num_len..];
                    let packet_number_int = BigEndian::read_i32(&packet_number);
                    offset += packet_num_len;
                    // Parse the encrypted payload
                    let tag_len = conn.client_opener.as_ref().unwrap().alg().tag_len();
                    if (packet_len.unwrap() as usize) < (tag_len + packet_num_len) {
                        return Err(QuicError::PacketTooShort);
                    }
                    let cipher_text_len = packet_len.unwrap() as usize - tag_len - packet_num_len;
                    let mut encrypted_payload =
                        QuicPacket::access_data(data, offset, offset + cipher_text_len)?.to_vec();
                    offset += cipher_text_len;
                    // Parse auth tag
                    let tag = QuicPacket::access_data(data, offset, offset + tag_len)?;
                    offset += tag_len;
                    // Reconstruct authenticated data
                    let mut ad = Vec::new();
                    ad.append(&mut [unprotected_header].to_vec());
                    ad.append(&mut version_bytes.to_vec());
                    ad.append(&mut [dcid_len].to_vec());
                    ad.append(&mut dcid_bytes.to_vec());
                    ad.append(&mut [scid_len].to_vec());
                    ad.append(&mut scid_bytes.to_vec());
                    ad.append(&mut token_len_bytes.to_vec());
                    ad.append(&mut token_bytes.to_vec());
                    ad.append(&mut packet_len_bytes.to_vec());
                    ad.append(&mut initial_packet_number_bytes.to_vec());
                    // Decrypt payload with proper keys based on traffic direction
                    if dir {
                        decrypted_payload =
                            Some(conn.client_opener.as_ref().unwrap().open_with_u64_counter(
                                packet_number_int as u64,
                                &ad,
                                &mut encrypted_payload,
                                tag,
                            )?);
                    } else {
                        decrypted_payload =
                            Some(conn.server_opener.as_ref().unwrap().open_with_u64_counter(
                                packet_number_int as u64,
                                &ad,
                                &mut encrypted_payload,
                                tag,
                            )?);
                    }
                }
                LongHeaderPacketType::ZeroRTT | LongHeaderPacketType::Handshake => {
                    token_len = None;
                    token = None;
                    retry_tag = None;
                    decrypted_payload = None;
                    // Parse payload length
                    let packet_len_len = QuicPacket::get_var_len(
                        QuicPacket::access_data(data, offset, offset + 1)?[0],
                    )?;
                    packet_len = Some(QuicPacket::slice_to_u64(QuicPacket::access_data(
                        data,
                        offset,
                        offset + packet_len_len,
                    )?)?);
                    offset += packet_len_len;
                    offset += packet_len.unwrap() as usize;
                }
                LongHeaderPacketType::Retry => {
                    packet_len = None;
                    decrypted_payload = None;
                    if data.len() > (offset + 16) {
                        token_len = Some((data.len() - offset - 16) as u64);
                    } else {
                        return Err(QuicError::PacketTooShort);
                    }
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
                    offset += 16;
                }
            }

            let mut frames: Option<Vec<QuicFrame>> = None;
            // Grab the proper buffer for CRYPTO frame data
            let crypto_buffer: &mut Vec<u8> = if dir {
                conn.client_buffer.as_mut()
            } else {
                conn.server_buffer.as_mut()
            };
            // If decrypted payload is not None, parse the frames
            if let Some(frame_bytes) = decrypted_payload {
                // Get frames and reassembled CRYPTO data
                // Pass the buffer's current length as starting offset for CRYPTO frames
                let (q_frames, mut crypto_bytes) =
                    QuicFrame::parse_frames(&frame_bytes, crypto_buffer.len())?;
                frames = Some(q_frames);
                if !crypto_bytes.is_empty() {
                    crypto_buffer.append(&mut crypto_bytes);
                    // Attempt to parse CRYPTO buffer
                    // clear on success
                    // TODO: This naive buffer will not work for out of order frames
                    // across packets or multiple messages in the same buffer
                    match parse_tls_message_handshake(crypto_buffer) {
                        Ok((_, msg)) => {
                            conn.tls.parse_message_level(&msg, dir);
                            crypto_buffer.clear();
                        }
                        Err(_) => return Err(QuicError::TlsParseFail),
                    }
                }
            }

            Ok((
                QuicPacket {
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
                    frames,
                },
                offset,
            ))
        } else {
            // Short Header
            let mut dcid_len = 20;
            if data.len() < 1 + dcid_len {
                dcid_len = data.len() - 1;
            }
            // Parse DCID
            let dcid_hex = QuicPacket::vec_u8_to_hex_string(QuicPacket::access_data(
                data,
                offset,
                offset + dcid_len,
            )?);
            let mut dcid = None;
            for cid in &conn.cids {
                if dcid_hex.starts_with(cid) {
                    dcid_len = cid.chars().count() / 2;
                    dcid = Some(cid.clone());
                }
            }
            offset += dcid_len;
            // Counts all bytes remaining
            let payload_bytes_count = (data.len() - offset) as u64;
            offset += payload_bytes_count as usize;
            Ok((
                QuicPacket {
                    short_header: Some(QuicShortHeader { dcid }),
                    long_header: None,
                    payload_bytes_count: Some(payload_bytes_count),
                    frames: None,
                },
                offset,
            ))
        }
    }
}

impl QuicConn {
    pub(crate) fn new() -> QuicConn {
        QuicConn {
            packets: Vec::new(),
            cids: HashSet::new(),
            tls: Tls::new(),
            client_opener: None,
            server_opener: None,
            client_buffer: Vec::new(),
            server_buffer: Vec::new(),
        }
    }

    fn parse_packet(&mut self, data: &[u8], direction: bool) -> ParseResult {
        let mut offset = 0;
        // Iterate over all of the data in the datagram
        // Parse as many QUIC packets as possible
        // TODO: identify padding appended to datagram
        while data.len() > offset {
            if let Ok((quic, off)) = QuicPacket::parse_from(self, data, offset, direction) {
                self.packets.push(quic);
                offset = off;
            } else {
                return ParseResult::Skipped;
            }
        }
        ParseResult::Continue(0)
    }
}
