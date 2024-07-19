// QUIC Frame types and parsing
// Implemented per RFC 9000: https://datatracker.ietf.org/doc/html/rfc9000#name-frame-types-and-formats

use serde::Serialize;
use std::collections::BTreeMap;

use crate::protocols::stream::quic::QuicError;
use crate::protocols::stream::quic::QuicPacket;

// Types of supported QUIC frames
// Currently only includes those seen in the Init and Handshake packets
#[derive(Debug, Serialize, Clone)]
pub enum QuicFrame {
    Padding {
        length: usize,
    },
    Ping,
    Ack {
        largest_acknowledged: u64,
        ack_delay: u64,
        first_ack_range: u64,
        ack_ranges: Vec<AckRange>,
        ecn_counts: Option<EcnCounts>,
    },
    Crypto {
        offset: u64,
    },
}

// ACK Range field, part of ACK frame
// https://datatracker.ietf.org/doc/html/rfc9000#ack-range-format
#[derive(Debug, Serialize, Clone)]
pub struct AckRange {
    gap: u64,
    ack_range_len: u64,
}

// ECN Counts field, part of some ACK frames
// https://datatracker.ietf.org/doc/html/rfc9000#ecn-count-format
#[derive(Debug, Serialize, Clone)]
pub struct EcnCounts {
    ect0_count: u64,
    ect1_count: u64,
    ecn_ce_count: u64,
}

impl QuicFrame {
    // parse_frames takes the plaintext QUIC packet payload and parses the frame list
    pub fn parse_frames(data: &[u8]) -> Result<(Vec<QuicFrame>, Vec<u8>), QuicError> {
        let mut frames: Vec<QuicFrame> = Vec::new();
        let mut crypto_map: BTreeMap<u64, Vec<u8>> = BTreeMap::new();
        let mut offset = 0;
        // Iterate over plaintext payload bytes, this is a list of frames
        while offset < data.len() {
            // Parse frame type
            let frame_type_len =
                QuicPacket::get_var_len(QuicPacket::access_data(data, offset, offset + 1)?[0])?;
            let frame_type = QuicPacket::slice_to_u64(QuicPacket::access_data(
                data,
                offset,
                offset + frame_type_len,
            )?)?;
            offset += frame_type_len;
            match frame_type {
                0x00 => {
                    // Handle PADDING
                    let mut length = 0;
                    while offset + length + 1 < data.len()
                        && QuicPacket::access_data(data, offset + length, offset + length + 1)?[0]
                            == 0
                    {
                        length += 1;
                    }
                    offset += length;
                    length += frame_type_len; // Add the original frame type bytes to length. Wireshark also does this
                    frames.push(QuicFrame::Padding { length });
                }
                0x01 => {
                    // Handle PING
                    frames.push(QuicFrame::Ping);
                }
                0x02 | 0x03 => {
                    // Handle ACK
                    // Parse Largest Acknowledged
                    let largest_acknowledged_len = QuicPacket::get_var_len(
                        QuicPacket::access_data(data, offset, offset + 1)?[0],
                    )?;
                    let largest_acknowledged = QuicPacket::slice_to_u64(QuicPacket::access_data(
                        data,
                        offset,
                        offset + largest_acknowledged_len,
                    )?)?;
                    offset += largest_acknowledged_len;
                    // Parse ACK Delay
                    let ack_delay_len = QuicPacket::get_var_len(
                        QuicPacket::access_data(data, offset, offset + 1)?[0],
                    )?;
                    let ack_delay = QuicPacket::slice_to_u64(QuicPacket::access_data(
                        data,
                        offset,
                        offset + ack_delay_len,
                    )?)?;
                    offset += ack_delay_len;
                    // Parse ACK Range Count
                    let ack_range_count_len = QuicPacket::get_var_len(
                        QuicPacket::access_data(data, offset, offset + 1)?[0],
                    )?;
                    let ack_range_count = QuicPacket::slice_to_u64(QuicPacket::access_data(
                        data,
                        offset,
                        offset + ack_range_count_len,
                    )?)?;
                    offset += ack_range_count_len;
                    // Parse First ACK Range
                    let first_ack_range_len = QuicPacket::get_var_len(
                        QuicPacket::access_data(data, offset, offset + 1)?[0],
                    )?;
                    let first_ack_range = QuicPacket::slice_to_u64(QuicPacket::access_data(
                        data,
                        offset,
                        offset + first_ack_range_len,
                    )?)?;
                    // Parse ACK Range list field
                    let mut ack_ranges = Vec::new();
                    for _ in 0..ack_range_count {
                        let gap_len = QuicPacket::get_var_len(
                            QuicPacket::access_data(data, offset, offset + 1)?[0],
                        )?;
                        let gap = QuicPacket::slice_to_u64(QuicPacket::access_data(
                            data,
                            offset,
                            offset + gap_len,
                        )?)?;
                        offset += gap_len;
                        let ack_range_len_len = QuicPacket::get_var_len(
                            QuicPacket::access_data(data, offset, offset + 1)?[0],
                        )?;
                        let ack_range_len = QuicPacket::slice_to_u64(QuicPacket::access_data(
                            data,
                            offset,
                            offset + ack_range_len_len,
                        )?)?;
                        offset += ack_range_len_len;
                        ack_ranges.push(AckRange { gap, ack_range_len })
                    }
                    // Parse ECN Counts, if the ACK frame contains them
                    let ecn_counts: Option<EcnCounts> = if frame_type == 0x03 {
                        let ect0_count_len = QuicPacket::get_var_len(
                            QuicPacket::access_data(data, offset, offset + 1)?[0],
                        )?;
                        let ect0_count = QuicPacket::slice_to_u64(QuicPacket::access_data(
                            data,
                            offset,
                            offset + ect0_count_len,
                        )?)?;
                        offset += ect0_count_len;
                        let ect1_count_len = QuicPacket::get_var_len(
                            QuicPacket::access_data(data, offset, offset + 1)?[0],
                        )?;
                        let ect1_count = QuicPacket::slice_to_u64(QuicPacket::access_data(
                            data,
                            offset,
                            offset + ect1_count_len,
                        )?)?;
                        offset += ect1_count_len;
                        let ecn_ce_count_len = QuicPacket::get_var_len(
                            QuicPacket::access_data(data, offset, offset + 1)?[0],
                        )?;
                        let ecn_ce_count = QuicPacket::slice_to_u64(QuicPacket::access_data(
                            data,
                            offset,
                            offset + ecn_ce_count_len,
                        )?)?;
                        Some(EcnCounts {
                            ect0_count,
                            ect1_count,
                            ecn_ce_count,
                        })
                    } else {
                        None
                    };
                    frames.push(QuicFrame::Ack {
                        largest_acknowledged,
                        ack_delay,
                        first_ack_range,
                        ack_ranges,
                        ecn_counts,
                    })
                }
                0x06 => {
                    // Handle CRYPTO frame
                    // Parse offset
                    let crypto_offset_len = QuicPacket::get_var_len(
                        QuicPacket::access_data(data, offset, offset + 1)?[0],
                    )?;
                    let crypto_offset = QuicPacket::slice_to_u64(QuicPacket::access_data(
                        data,
                        offset,
                        offset + crypto_offset_len,
                    )?)?;
                    offset += crypto_offset_len;
                    // Parse length
                    let crypto_len_len = QuicPacket::get_var_len(
                        QuicPacket::access_data(data, offset, offset + 1)?[0],
                    )?;
                    let crypto_len = QuicPacket::slice_to_u64(QuicPacket::access_data(
                        data,
                        offset,
                        offset + crypto_len_len,
                    )?)? as usize;
                    offset += crypto_len_len;
                    // Parse data
                    let crypto_data =
                        QuicPacket::access_data(data, offset, offset + crypto_len)?.to_vec();
                    crypto_map.entry(crypto_offset).or_insert(crypto_data);
                    frames.push(QuicFrame::Crypto {
                        offset: crypto_offset,
                    });
                    offset += crypto_len;
                }
                _ => return Err(QuicError::UnknownFrameType),
            }
        }
        let mut reassembled_crypto: Vec<u8> = Vec::new();
        let mut expected_offset: u64 = 0;
        for (crypto_offset, crypto_data) in crypto_map {
            if crypto_offset != expected_offset {
                return Err(QuicError::MissingCryptoFrames);
            }
            reassembled_crypto.extend(crypto_data);
            expected_offset = reassembled_crypto.len() as u64;
        }
        Ok((frames, reassembled_crypto))
    }
}
