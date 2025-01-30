//! Various individual connection-level subscribable types for TCP and/or UDP
//! connection information, statistics, and state history.

use crate::Tracked;
use retina_core::L4Pdu;
use serde::ser::{Serialize, SerializeSeq, SerializeStruct, Serializer};
use std::time::{Duration, Instant};

/// Tracks the start (first packet seen) and end (last packet seen)
/// times of a connection
#[derive(Debug, Clone)]
pub struct ConnDuration {
    pub start_ts: Instant,
    pub last_ts: Instant,
}

impl Serialize for ConnDuration {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("ConnDuration", 1)?;

        let duration = self.last_ts - self.start_ts;
        state.serialize_field("duration", &duration.as_millis())?;
        state.end()
    }
}

impl ConnDuration {
    /// The duration of the connection in milliseconds
    pub fn duration_ms(&self) -> u128 {
        (self.last_ts - self.start_ts).as_millis()
    }

    /// The duration of the connection as std::time::Duration
    pub fn duration(&self) -> Duration {
        self.last_ts - self.start_ts
    }
}

impl Tracked for ConnDuration {
    fn new(_first_pkt: &L4Pdu) -> Self {
        let now = Instant::now();
        Self {
            start_ts: now,
            last_ts: now,
        }
    }

    #[inline]
    fn clear(&mut self) {}

    #[inline]
    fn update(&mut self, _pdu: &L4Pdu, reassembled: bool) {
        if !reassembled {
            self.last_ts = Instant::now();
        }
    }

    fn stream_protocols() -> Vec<&'static str> {
        vec![]
    }
}

/// The number of packets observed in a connection
#[derive(Debug, serde::Serialize, Clone)]
pub struct PktCount {
    pub pkt_count: usize,
}

impl PktCount {
    pub fn raw(&self) -> usize {
        self.pkt_count
    }
}

impl Tracked for PktCount {
    fn new(_first_pkt: &L4Pdu) -> Self {
        Self { pkt_count: 0 }
    }

    #[inline]
    fn clear(&mut self) {}

    #[inline]
    fn update(&mut self, _pdu: &L4Pdu, reassembled: bool) {
        if !reassembled {
            self.pkt_count += 1;
        }
    }

    fn stream_protocols() -> Vec<&'static str> {
        vec![]
    }
}

/// The number of bytes, including headers, observed in a connection
#[derive(Debug, serde::Serialize, Clone)]
pub struct ByteCount {
    pub byte_count: usize,
}

impl ByteCount {
    pub fn raw(&self) -> usize {
        self.byte_count
    }
}

impl Tracked for ByteCount {
    fn new(_first_pkt: &L4Pdu) -> Self {
        Self { byte_count: 0 }
    }

    #[inline]
    fn clear(&mut self) {}

    #[inline]
    fn update(&mut self, pdu: &L4Pdu, reassembled: bool) {
        if !reassembled {
            self.byte_count += pdu.mbuf_ref().data_len();
        }
    }

    fn stream_protocols() -> Vec<&'static str> {
        vec![]
    }
}

/// Tracked data for packet inter-arrival times
#[derive(Debug, Clone)]
pub struct InterArrivals {
    pkt_count_ctos: usize,
    pkt_count_stoc: usize,
    last_pkt_ctos: Instant,
    last_pkt_stoc: Instant,
    pub interarrivals_ctos: Vec<Duration>,
    /// Interarrival durations server-to-client (resp.) flow
    pub interarrivals_stoc: Vec<Duration>,
}

impl InterArrivals {
    pub fn new_empty() -> Self {
        let now = Instant::now();
        Self {
            pkt_count_ctos: 0,
            pkt_count_stoc: 0,
            last_pkt_ctos: now,
            last_pkt_stoc: now,
            interarrivals_ctos: Vec::new(),
            interarrivals_stoc: Vec::new(),
        }
    }
}

impl Tracked for InterArrivals {
    fn new(_first_pkt: &L4Pdu) -> Self {
        Self::new_empty()
    }

    #[inline]
    fn clear(&mut self) {}

    #[inline]
    fn update(&mut self, pdu: &L4Pdu, reassembled: bool) {
        if !reassembled {
            let now = Instant::now();
            if pdu.dir {
                self.pkt_count_ctos += 1;
                if self.pkt_count_ctos > 1 {
                    self.interarrivals_ctos.push(now - self.last_pkt_ctos);
                }
                self.last_pkt_stoc = now;
            } else {
                self.pkt_count_stoc += 1;
                if self.pkt_count_stoc > 1 {
                    self.interarrivals_stoc.push(now - self.last_pkt_stoc);
                }
                self.last_pkt_stoc = now;
            }
        }
    }

    fn stream_protocols() -> Vec<&'static str> {
        vec![]
    }
}

struct DurationVec<'a>(&'a Vec<Duration>);
impl Serialize for DurationVec<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut seq = serializer.serialize_seq(Some(self.0.len()))?;
        for dur in self.0 {
            seq.serialize_element(&dur.as_nanos())?;
        }
        seq.end()
    }
}

impl Serialize for InterArrivals {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("InterArrivals", 4)?;
        state.serialize_field("interarrivals_ctos", &DurationVec(&self.interarrivals_ctos))?;
        state.serialize_field("interarrivals_stoc", &DurationVec(&self.interarrivals_stoc))?;
        state.end()
    }
}

use crate::connection::update_history;

/// Connection history.
///
/// This represents a summary of the connection history in the order the packets were observed,
/// with letters encoded as a vector of bytes. This is a simplified version of [state history in
/// Zeek](https://docs.zeek.org/en/v5.0.0/scripts/base/protocols/conn/main.zeek.html), and the
/// meanings of each letter are similar: If the event comes from the originator, the letter is
/// uppercase; if the event comes from the responder, the letter is lowercase.
/// - S: a pure SYN with only the SYN bit set (may have payload)
/// - H: a pure SYNACK with only the SYN and ACK bits set (may have payload)
/// - A: a pure ACK with only the ACK bit set and no payload
/// - D: segment contains non-zero payload length
/// - F: the segment has the FIN bit set (may have other flags and/or payload)
/// - R: segment has the RST bit set (may have other flags and/or payload)
///
/// Each letter is recorded a maximum of once in either direction.
#[derive(Default, Debug, serde::Serialize, Clone)]
pub struct ConnHistory {
    pub history: Vec<u8>,
}

impl Tracked for ConnHistory {
    fn new(_first_pkt: &L4Pdu) -> Self {
        Self {
            history: Vec::with_capacity(16),
        }
    }

    #[inline]
    fn clear(&mut self) {}

    #[inline]
    fn update(&mut self, pdu: &L4Pdu, reassembled: bool) {
        if !reassembled {
            if pdu.dir {
                update_history(&mut self.history, pdu, 0x0);
            } else {
                update_history(&mut self.history, pdu, 0x20);
            }
        }
    }

    fn stream_protocols() -> Vec<&'static str> {
        vec![]
    }
}
