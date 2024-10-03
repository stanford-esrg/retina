use std::time::Instant;
use retina_core::protocols::Session;
use retina_core::L4Pdu;
use crate::Tracked;
use serde::ser::{Serialize, Serializer, SerializeStruct};

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


pub struct PktCount {
    pub pkt_count: usize,
}

impl Tracked for PktCount {
    fn new(_first_pkt: &L4Pdu) -> Self {
        Self {
            pkt_count: 0,
        }
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

pub struct ByteCount {
    pub byte_count: usize,
}

impl Tracked for ByteCount {
    fn new(_first_pkt: &L4Pdu) -> Self {
        Self {
            byte_count: 0,
        }
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