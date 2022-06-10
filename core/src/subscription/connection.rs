//! Connection records.
//!
//! This is a connection-level subscription that provides TCP and/or UDP connection information,
//! statistics, and state history. It does not deliver payload data.
//!
//!
//! ## Example
//! Logs TCP/22 and TCP/23 connection records to a file:
//! ```
//! #[filter("tcp.port = 80 or tcp.port = 443")]
//! fn main() {
//!     let config = default_config();
//!     let file = Mutex::new(File::create("conn.jsonl").unwrap());
//!     let cb = |conn: Connection| {
//!         let mut wtr = file.lock().unwrap();
//!         jsonl::write(&mut *wtr, &conn).unwrap();
//!     };
//!     let mut runtime = Runtime::new(config, filter, cb).unwrap();
//!     runtime.run();
//! }
//! ```

use crate::conntrack::conn::tcp_conn::reassembly::wrapping_lt;
use crate::conntrack::conn_id::FiveTuple;
use crate::conntrack::pdu::{L4Context, L4Pdu};
use crate::conntrack::ConnTracker;
use crate::filter::FilterResult;
use crate::memory::mbuf::Mbuf;
use crate::protocols::packet::tcp::{ACK, FIN, RST, SYN};
use crate::protocols::stream::{ConnParser, Session};
use crate::subscription::{Level, Subscribable, Subscription, Trackable};

use serde::ser::{SerializeStruct, Serializer};
use serde::Serialize;

use std::collections::HashMap;
use std::fmt;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

/// Pure SYN
const HIST_SYN: u8 = b'S';
/// Pure SYNACK
const HIST_SYNACK: u8 = b'H';
/// Pure ACK (no payload)
const HIST_ACK: u8 = b'A';
/// Has non-zero payload length
const HIST_DATA: u8 = b'D';
/// Has FIN set
const HIST_FIN: u8 = b'F';
/// Has RST set
const HIST_RST: u8 = b'R';

/// A connection record.
///
/// This subscribable type returns general information regarding TCP and UDP connections but does
/// does not track payload data. If applicable, Retina internally manages stream reassembly. All
/// connections are interpreted using flow semantics.
#[derive(Debug)]
pub struct Connection {
    /// The connection 5-tuple.
    pub five_tuple: FiveTuple,
    /// Timestamp of the first packet.
    ///
    /// ## Remarks
    /// This represents the time Retina observed the first packet in the connection, and does not
    /// reflect timestamps read from a packet capture in offline analysis.
    // TODO: embed a hardware timestamp in the Mbuf itself.
    pub ts: Instant,
    /// The duration of the connection.
    ///
    /// ## Remarks
    /// This does not represent the actual duration of the connection in offline analysis. It
    /// approximates the elapsed time between observation of the first and last observed packet in
    /// the connection.
    pub duration: Duration,
    /// Maximum duration of inactivity (the maximum time between observed segments).
    pub max_inactivity: Duration,
    /// The duration between the first and second packets.
    pub time_to_second_packet: Duration,
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
    pub history: Vec<u8>,
    /// Originator flow.
    pub orig: Flow,
    /// Responder flow.
    pub resp: Flow,
}

impl Connection {
    /// Returns the client (originator) socket address.
    #[inline]
    pub fn client(&self) -> SocketAddr {
        self.five_tuple.orig
    }

    /// Returns the server (responder) socket address.
    #[inline]
    pub fn server(&self) -> SocketAddr {
        self.five_tuple.resp
    }

    /// Returns the total number of packets observed in the connection.
    #[inline]
    pub fn total_pkts(&self) -> u64 {
        self.orig.nb_pkts + self.resp.nb_pkts
    }

    /// Returns the total number of payload bytes observed, excluding those from malformed packets.
    #[inline]
    pub fn total_bytes(&self) -> u64 {
        self.orig.nb_bytes + self.resp.nb_bytes
    }

    /// Returns the connection history.
    #[inline]
    pub fn history(&self) -> String {
        String::from_utf8_lossy(&self.history).into_owned()
    }
}

impl Serialize for Connection {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("Connection", 6)?;
        state.serialize_field("five_tuple", &self.five_tuple)?;
        state.serialize_field("duration", &self.duration)?;
        state.serialize_field("max_inactivity", &self.max_inactivity)?;
        state.serialize_field("history", &self.history())?;
        state.serialize_field("orig", &self.orig)?;
        state.serialize_field("resp", &self.resp)?;
        state.end()
    }
}

impl fmt::Display for Connection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.five_tuple, self.history())?;
        Ok(())
    }
}

impl Subscribable for Connection {
    type Tracked = TrackedConnection;

    fn level() -> Level {
        Level::Connection
    }

    // TODO: return a vector of all known parsers.
    fn parsers() -> Vec<ConnParser> {
        vec![]
    }

    fn process_packet(
        mbuf: Mbuf,
        subscription: &Subscription<Self>,
        conn_tracker: &mut ConnTracker<Self::Tracked>,
    ) {
        match subscription.filter_packet(&mbuf) {
            FilterResult::MatchTerminal(idx) | FilterResult::MatchNonTerminal(idx) => {
                if let Ok(ctxt) = L4Context::new(&mbuf, idx) {
                    conn_tracker.process(mbuf, ctxt, subscription);
                }
            }
            FilterResult::NoMatch => drop(mbuf),
        }
    }
}

/// Tracks a connection record throughout its lifetime.
///
/// ## Note
/// Internal connection state is an associated type of a `pub` trait, and therefore must also be
/// public. Documentation is hidden by default to avoid confusing users.
#[doc(hidden)]
pub struct TrackedConnection {
    five_tuple: FiveTuple,
    first_seen_ts: Instant,
    second_seen_ts: Instant,
    last_seen_ts: Instant,
    max_inactivity: Duration,
    history: Vec<u8>,
    ctos: Flow,
    stoc: Flow,
}

impl TrackedConnection {
    #[inline]
    fn update(&mut self, segment: L4Pdu) {
        let now = Instant::now();
        let inactivity = now - self.last_seen_ts;
        if inactivity > self.max_inactivity {
            self.max_inactivity = inactivity;
        }
        self.last_seen_ts = now;

        if segment.dir {
            self.update_history(&segment, 0x0);
            self.ctos.insert_segment(segment);
        } else {
            self.update_history(&segment, 0x20);
            self.stoc.insert_segment(segment);
        }

        if self.ctos.nb_pkts + self.stoc.nb_pkts == 2 {
            self.second_seen_ts = now;
        }
    }

    #[inline]
    fn update_history(&mut self, segment: &L4Pdu, mask: u8) {
        fn insert(history: &mut Vec<u8>, event: u8) {
            if !history.contains(&event) {
                history.push(event);
            }
        }
        if segment.flags() == SYN {
            insert(&mut self.history, HIST_SYN ^ mask);
        } else if segment.flags() == (SYN | ACK) {
            insert(&mut self.history, HIST_SYNACK ^ mask);
        } else if segment.flags() == ACK && segment.length() == 0 {
            insert(&mut self.history, HIST_ACK ^ mask);
        }

        if segment.flags() & FIN != 0 {
            insert(&mut self.history, HIST_FIN ^ mask);
        }
        if segment.flags() & RST != 0 {
            insert(&mut self.history, HIST_RST ^ mask);
        }
        if segment.length() > 0 {
            insert(&mut self.history, HIST_DATA ^ mask);
        }
    }
}

impl Trackable for TrackedConnection {
    type Subscribed = Connection;

    fn new(five_tuple: FiveTuple) -> Self {
        let now = Instant::now();
        TrackedConnection {
            five_tuple,
            first_seen_ts: now,
            second_seen_ts: now,
            last_seen_ts: now,
            max_inactivity: Duration::default(),
            history: Vec::with_capacity(16),
            ctos: Flow::new(),
            stoc: Flow::new(),
        }
    }

    fn pre_match(&mut self, pdu: L4Pdu, _session_id: Option<usize>) {
        self.update(pdu);
    }

    fn on_match(&mut self, _session: Session, _subscription: &Subscription<Self::Subscribed>) {
        // do nothing, should stay tracked
    }

    fn post_match(&mut self, pdu: L4Pdu, _subscription: &Subscription<Self::Subscribed>) {
        self.update(pdu)
    }

    fn on_terminate(&mut self, subscription: &Subscription<Self::Subscribed>) {
        let (duration, max_inactivity, time_to_second_packet) =
            if self.ctos.nb_pkts + self.stoc.nb_pkts == 1 {
                (
                    Duration::default(),
                    Duration::default(),
                    Duration::default(),
                )
            } else {
                (
                    self.last_seen_ts - self.first_seen_ts,
                    self.max_inactivity,
                    self.second_seen_ts - self.first_seen_ts,
                )
            };

        let conn = Connection {
            five_tuple: self.five_tuple,
            ts: self.first_seen_ts,
            duration,
            max_inactivity,
            time_to_second_packet,
            history: self.history.clone(),
            orig: self.ctos.clone(),
            resp: self.stoc.clone(),
        };
        subscription.invoke(conn);
    }
}

/// A uni-directional flow.
#[derive(Debug, Clone, Serialize)]
pub struct Flow {
    /// Number of packets seen for this flow, including malformed and late start segments.
    ///
    /// - Malformed segments are defined as those that have a payload offset (start of the payload,
    ///   as computed from the header length field) beyond the end of the packet buffer, or the end
    ///   of the payload exceeds the end of the packet buffer.
    /// - Late start segments are those that arrive after the first packet seen in the flow, but
    ///   have an earlier sequence number. Only applies to TCP flows.
    pub nb_pkts: u64,
    /// Number of malformed packets.
    pub nb_malformed_pkts: u64,
    /// Number of late start packets.
    pub nb_late_start_pkts: u64,
    /// Number of payload bytes observed in the flow. Does not include bytes from malformed
    /// segments.
    pub nb_bytes: u64,
    /// Maximum number of simultaneous content gaps.
    ///
    /// A content gap is a "hole" in the TCP sequence number, indicated re-ordered or missing
    /// packets. Only applies to TCP flows.
    pub max_simult_gaps: u64,
    /// Starting sequence number of the first byte in the first payload (ISN + 1). Only applies to
    /// TCP flows, and is set to `0` for UDP.
    pub data_start: u32,
    /// Maximum chunk capacity (the maximum number of simultaneous gaps + 1). Only applies to TCP
    /// flows.
    pub capacity: usize,
    /// The set of non-overlapping content intervals. Only applies to TCP flows.
    pub chunks: Vec<Chunk>,
    /// Maps relative sequence number of a content gap to the number of packets observed before it
    /// is filled. Only applies to TCP flows.
    pub gaps: HashMap<u32, u64>,
}

impl Flow {
    fn new() -> Self {
        Flow {
            nb_pkts: 0,
            nb_malformed_pkts: 0,
            nb_late_start_pkts: 0,
            nb_bytes: 0,
            max_simult_gaps: 0,
            data_start: 0,
            capacity: 100, // temp hardcode for now
            chunks: Vec::with_capacity(100),
            gaps: HashMap::new(),
        }
    }

    #[inline]
    fn insert_segment(&mut self, segment: L4Pdu) {
        self.nb_pkts += 1;

        if segment.offset() > segment.mbuf.data_len()
            || (segment.offset() + segment.length()) > segment.mbuf.data_len()
        {
            self.nb_malformed_pkts += 1;
            return;
        }
        self.nb_bytes += segment.length() as u64;

        let seq_no = if segment.flags() & SYN != 0 {
            segment.seq_no().wrapping_add(1)
        } else {
            segment.seq_no()
        };

        if self.chunks.is_empty() {
            self.data_start = seq_no;
        }

        if wrapping_lt(seq_no, self.data_start) {
            self.nb_late_start_pkts += 1;
            return;
        }

        if self.chunks.len() < self.capacity {
            let seg_start = seq_no.wrapping_sub(self.data_start);
            let seg_end = seg_start + segment.length() as u32;

            self.merge_chunk(Chunk(seg_start, seg_end));
        }
    }

    /// Insert `chunk` into flow, merging intervals as necessary. Flow `chunks` are a sorted set of
    /// non-overlapping intervals.
    #[inline]
    fn merge_chunk(&mut self, chunk: Chunk) {
        let mut start = chunk.0;
        let mut end = chunk.1;

        let mut result = vec![];
        let mut inserted = false;
        for chunk in self.chunks.iter() {
            if inserted || start > chunk.1 {
                result.push(*chunk);
            } else if end < chunk.0 {
                inserted = true;
                result.push(Chunk(start, end));
                result.push(*chunk);
            } else {
                start = std::cmp::min(start, chunk.0);
                end = std::cmp::max(end, chunk.1);
            }
        }
        if !inserted {
            result.push(Chunk(start, end));
        }

        for chunk in result[..result.len() - 1].iter() {
            *self.gaps.entry(chunk.1).or_insert(0) += 1;
        }

        if result.len().saturating_sub(1) as u64 > self.max_simult_gaps {
            self.max_simult_gaps += 1;
        }
        self.chunks = result;
    }

    /// Returns the number of content gaps at the connection end.
    ///
    /// This is not the total number of content gaps ever observed, rather, it represents the total
    /// number of gaps remaining in the final state of the connection.
    #[inline]
    pub fn content_gaps(&self) -> u64 {
        self.chunks.len().saturating_sub(1) as u64
    }

    /// Number of bytes missed in content gaps at connection end.
    ///
    /// This is not the total size of all content gaps ever observed, rather, it represents the
    /// total number of missing bytes in the final state of the connection.
    #[inline]
    pub fn missed_bytes(&self) -> u64 {
        self.chunks.windows(2).map(|w| w[1].0 - w[0].1).sum::<u32>() as u64
    }

    /// Returns the mean number of packet arrivals before a content gap is filled, or `0` if there
    /// were no gaps.
    #[inline]
    pub fn mean_pkts_to_fill(&self) -> Option<f64> {
        if self.gaps.is_empty() {
            return None;
        }
        let mut sum = 0;
        for val in self.gaps.values() {
            sum += *val;
        }
        Some(sum as f64 / self.gaps.len() as f64)
    }

    /// Returns the median number of packet arrivals before a content gap is filled, or `0` if there
    /// were no gaps.
    #[inline]
    pub fn median_pkts_to_fill(&self) -> Option<u64> {
        if self.gaps.is_empty() {
            return None;
        }
        let mut values = self.gaps.values().collect::<Vec<_>>();
        values.sort();
        let mid = values.len() / 2;
        Some(*values[mid])
    }
}

/// Start (inclusive) and end (exclusive) interval of contiguous TCP payload bytes.
#[derive(Debug, Default, Clone, Copy, Eq, PartialEq, Serialize)]
pub struct Chunk(u32, u32);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn core_merge_chunk_fill_single() {
        let mut flow = Flow::new();
        flow.chunks = vec![Chunk(0, 3), Chunk(4, 5)];
        flow.merge_chunk(Chunk(3, 4));
        assert_eq!(flow.chunks, vec![Chunk(0, 5)]);
    }

    #[test]
    fn core_merge_chunk_fill_multiple() {
        let mut flow = Flow::new();
        flow.chunks = vec![Chunk(0, 3), Chunk(4, 5), Chunk(8, 10)];
        flow.merge_chunk(Chunk(2, 12));
        assert_eq!(flow.chunks, vec![Chunk(0, 12)]);
    }

    #[test]
    fn core_merge_chunk_create_hole() {
        let mut flow = Flow::new();
        flow.chunks = vec![Chunk(0, 3), Chunk(8, 10)];
        flow.merge_chunk(Chunk(4, 5));
        assert_eq!(flow.chunks, vec![Chunk(0, 3), Chunk(4, 5), Chunk(8, 10)]);
    }

    #[test]
    fn core_merge_chunk_fill_overlap() {
        let mut flow = Flow::new();
        flow.chunks = vec![Chunk(0, 3), Chunk(8, 10)];
        flow.merge_chunk(Chunk(5, 9));
        assert_eq!(flow.chunks, vec![Chunk(0, 3), Chunk(5, 10)]);
    }

    #[test]
    fn core_merge_chunk_start() {
        let mut flow = Flow::new();
        flow.chunks = vec![Chunk(4, 6), Chunk(8, 10)];
        flow.merge_chunk(Chunk(0, 2));
        assert_eq!(flow.chunks, vec![Chunk(0, 2), Chunk(4, 6), Chunk(8, 10)]);
    }

    #[test]
    fn core_merge_chunk_end() {
        let mut flow = Flow::new();
        flow.chunks = vec![Chunk(4, 6), Chunk(8, 10)];
        flow.merge_chunk(Chunk(11, 15));
        assert_eq!(flow.chunks, vec![Chunk(4, 6), Chunk(8, 10), Chunk(11, 15)]);
    }
}
