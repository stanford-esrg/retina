use std::time::Instant;
use retina_core::protocols::Session;
use retina_core::L4Pdu;
use crate::Tracked;
use serde::ser::{Serialize, Serializer, SerializeStruct};


#[derive(Debug)]
pub struct ByteCounter {
    pub pkt_count: usize,
    pub byte_count: usize,
    pub start_ts: Instant,
    pub last_ts: Instant,
}

impl Serialize for ByteCounter {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("MyStruct", 2)?;

        let duration = self.last_ts - self.start_ts;

        state.serialize_field("pkts", &self.pkt_count)?;
        state.serialize_field("bytes", &self.byte_count)?;
        state.serialize_field("duration", &duration.as_millis())?;
        state.end()
    }
}

impl ByteCounter {
    pub fn duration_ms(&self) -> u128 {
        (self.last_ts - self.start_ts).as_millis()
    }
}

impl Tracked for ByteCounter {
    fn new(_first_pkt: &L4Pdu) -> Self {
        let now = Instant::now();
        Self {
            pkt_count: 0,
            byte_count: 0,
            start_ts: now,
            last_ts: now,
        }
    }

    fn clear(&mut self) {}

    fn update(&mut self, pdu: &L4Pdu, _reassembled: bool) {
        self.pkt_count += 1;
        self.byte_count += pdu.length();
        self.last_ts = Instant::now();
    }

    fn session_matched(&mut self, _session: &Session) {}

    fn stream_protocols() -> Vec<&'static str> {
        vec![]
    }
}