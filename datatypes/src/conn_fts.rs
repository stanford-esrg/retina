use crate::Tracked;
use retina_core::protocols::Session;
use retina_core::L4Pdu;
use serde::ser::{Serialize, SerializeSeq, SerializeStruct, Serializer};
use std::time::{Duration, Instant};

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
    pub fn duration_ms(&self) -> u128 {
        (self.last_ts - self.start_ts).as_millis()
    }

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

    #[inline]
    fn session_matched(&mut self, _session: &Session) {}

    fn stream_protocols() -> Vec<&'static str> {
        vec![]
    }
}

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

    #[inline]
    fn session_matched(&mut self, _session: &Session) {}

    fn stream_protocols() -> Vec<&'static str> {
        vec![]
    }
}

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

    #[inline]
    fn session_matched(&mut self, _session: &Session) {}

    fn stream_protocols() -> Vec<&'static str> {
        vec![]
    }
}

#[derive(Debug, Clone)]
pub struct InterArrivals {
    pub pkt_count_ctos: usize,
    pub pkt_count_stoc: usize,
    pub last_pkt_ctos: Instant,
    pub last_pkt_stoc: Instant,
    pub interarrivals_ctos: Vec<Duration>,
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

    #[inline]
    fn session_matched(&mut self, _session: &Session) {}

    fn stream_protocols() -> Vec<&'static str> {
        vec![]
    }
}

struct DurationVec<'a>(&'a Vec<Duration>);
impl<'a> Serialize for DurationVec<'a> {
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
        state.serialize_field("pkt_count_ctos", &self.pkt_count_ctos)?;
        state.serialize_field("pkt_count_stoc", &self.pkt_count_stoc)?;
        state.serialize_field("interarrivals_ctos", &DurationVec(&self.interarrivals_ctos))?;
        state.serialize_field("interarrivals_stoc", &DurationVec(&self.interarrivals_stoc))?;
        state.end()
    }
}

use crate::connection::update_history;

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

    #[inline]
    fn session_matched(&mut self, _session: &Session) {}

    fn stream_protocols() -> Vec<&'static str> {
        vec![]
    }
}
