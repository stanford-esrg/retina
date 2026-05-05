//! Connection byte streams.

use crate::conntrack::tcptrack::tcp_context;
use crate::subscription::*;

#[derive(Debug, Eq, PartialEq, Clone, Copy)]
pub enum Direction {
    FromOriginator,
    FromResponder,
}

/// Streams with payload in chunks of `capacity`. Will not invoke callback
/// on 0-sized chunks.
#[derive(Debug)]
pub struct Stream {
    pub five_tuple: FiveTuple,
    /// Byte buffer
    pub data: Vec<u8>,
    /// Direction
    pub direction: Direction,
}

impl Subscribable for Stream {
    type Interm = IntermStream;

    fn needs_reassembly() -> bool {
        true
    }

    fn applayer_parser() -> Option<Parser> {
        None
    }

    fn process_packet(
        mbuf: Mbuf,
        subscription: &Subscription<Self>,
        stream_table: &mut ConnTracker<Self::Interm>,
    ) {
        match subscription.packet_filter(&mbuf) {
            PacketFilterResult::MatchTerminal(idx) | PacketFilterResult::MatchNonTerminal(idx) => {
                // log::debug!("MATCH {:?}", idx);
                // check info - tryparse as TCP, if not then drop
                if let Ok(ctxt) = tcp_context(&mbuf, idx) {
                    stream_table.tcp_process(mbuf, ctxt, subscription);
                } else {
                    drop(mbuf);
                }
            }
            _ => {
                // log::debug!("NO MATCH!");
                drop(mbuf);
            }
        }
    }
}

#[derive(Debug)]
pub(crate) struct Flow {
    /// Maximum payload chunk size to deliver at a time
    max_chunk_size: usize,
    // /// Number of bytes in current buffer
    // size: usize,
    // /// Flow buffer of Payloads
    // payloads: Vec<Payload>,
    /// Flow buffer of bytes
    bytes: Vec<u8>,
}

impl Flow {
    fn new(max_chunk_size: usize) -> Self {
        Flow {
            max_chunk_size,
            // size: 0,
            // payloads: Vec::new(),
            bytes: Vec::new(),
        }
    }

    // /// Appends new nonzero length payload to stream always, regardless of `max_chunk_size`
    // fn append_payload(&mut self, payload: Payload) {
    //     self.size += payload.length();
    //     self.payloads.push(payload);
    // }

    /// Appends new nonzero length payload payload to stream always, regardless of `max_chunk_size`
    fn append_bytes(&mut self, payload: Payload) {
        if let Ok(data) = (payload.mbuf).get_data_slice(payload.offset(), payload.length()) {
            self.bytes.extend_from_slice(data);
        } else {
            log::error!("Malformed packet in stream. Dropping.");
        }
    }

    // /// Appends new nonzero payload to stream, delivers stream chunk if length will exceed `max_chunk_size`.
    // fn append_payload_chunked(&mut self, payload: Payload) -> Option<Vec<u8>> {
    //     let new_len = self.size + payload.length();
    //     if new_len > self.max_chunk_size {
    //         let to_deliver = self.payload_full();
    //         self.size = payload.length();
    //         self.payloads.push(payload);
    //         Some(to_deliver)
    //     } else {
    //         self.size = new_len;
    //         self.payloads.push(payload);
    //         None
    //     }
    // }

    /// Appends new nonzero payload payload to stream.
    /// Delivers stream chunk if length will exceed `max_chunk_size`.
    fn append_bytes_chunked(&mut self, payload: Payload) -> Option<Vec<u8>> {
        if let Ok(data) = (payload.mbuf).get_data_slice(payload.offset(), payload.length()) {
            let new_len = self.bytes.len() + data.len();
            if new_len > self.max_chunk_size {
                // delivers entire buffer and clears it
                let to_deliver = self.payload_full();
                self.bytes.extend_from_slice(data);
                return Some(to_deliver);
            } else {
                self.bytes.extend_from_slice(data);
                return None;
            }
        } else {
            log::error!("Malformed packet in stream. Dropping.");
        }
        None
    }

    // /// Returns full payload chunk from current buffered payloads.
    // /// Drains entire payload buffer.
    // fn payload_full(&mut self) -> Vec<u8> {
    //     let mut to_deliver = Vec::with_capacity(self.max_chunk_size);
    //     for seg in self.payloads.drain(..) {
    //         if let Ok(data) = (seg.mbuf).get_data_slice(seg.offset(), seg.length()) {
    //             to_deliver.extend_from_slice(data);
    //         } else {
    //             log::error!("Malformed packet in stream. Dropping.");
    //         }
    //     }
    //     self.size = 0;
    //     to_deliver
    // }

    /// Returns full payload chunk from current buffered bytes.
    /// Drains entire byte buffer.
    #[inline]
    fn payload_full(&mut self) -> Vec<u8> {
        let to_deliver = self.bytes.clone();
        self.bytes.clear();
        to_deliver
    }

    // /// Returns partial payload chunk of at most `max_chunk_size` from current buffered payloads.
    // /// Partially drains payload buffer.
    // fn payload_partial(&mut self) -> Vec<u8> {
    //     let mut end = 0;
    //     let mut length = 0;
    //     for seg in self.payloads.iter() {
    //         length += seg.length();
    //         if length > self.max_chunk_size {
    //             break;
    //         }
    //         end += 1;
    //     }
    //     let mut to_deliver = Vec::with_capacity(self.max_chunk_size);
    //     for seg in self.payloads.drain(..end) {
    //         if let Ok(data) = (seg.mbuf).get_data_slice(seg.offset(), seg.length()) {
    //             to_deliver.extend_from_slice(data);
    //         } else {
    //             log::error!("Malformed packet in stream. Dropping.");
    //         }
    //         self.size -= seg.length();
    //     }
    //     to_deliver
    // }

    // /// Returns partial payload chunk of at most `max_chunk_size` from current buffered bytes.
    // /// Partially drains byte buffer.
    // #[inline]
    // fn payload_partial(&mut self) -> Vec<u8> {
    //     let end = std::cmp::min(self.bytes.len(), self.max_chunk_size);

    //     let mut to_deliver = Vec::with_capacity(self.max_chunk_size);
    //     for b in self.bytes.drain(..end) {
    //         to_deliver.push(b)
    //     }
    //     to_deliver
    // }
}

pub struct IntermStream {
    pub(crate) five_tuple: FiveTuple,
    /// maximum payload chunk size to deliver at a time
    pub(crate) max_chunk_size: usize,
    pub(crate) ctos: Flow,
    pub(crate) stoc: Flow,
}

impl IntermStream {
    fn deliver_chunked(&mut self, direction: Direction, subscription: &Subscription<Stream>) {
        let bytes = match direction {
            Direction::FromOriginator => &mut self.ctos.bytes,
            Direction::FromResponder => &mut self.stoc.bytes,
        };
        let mut start_idx = 0;
        let mut size = bytes.len();
        while size > 0 {
            let mut to_deliver;
            if size > self.max_chunk_size {
                to_deliver = vec![0; self.max_chunk_size];
                to_deliver.copy_from_slice(&bytes[start_idx..start_idx + self.max_chunk_size]);
                size -= self.max_chunk_size;
                start_idx += self.max_chunk_size;
            } else {
                to_deliver = vec![0; size];
                to_deliver.copy_from_slice(&bytes[start_idx..start_idx + size]);
                size = 0;
            }
            let stream = Stream {
                five_tuple: self.five_tuple,
                data: to_deliver,
                direction,
            };
            subscription.invoke(stream);
        }
        bytes.clear();
    }
}

impl Reassembled for IntermStream {
    type Output = Stream;

    fn new(five_tuple: FiveTuple) -> Self {
        IntermStream {
            five_tuple,
            max_chunk_size: 8000,
            ctos: Flow::new(8000),
            stoc: Flow::new(8000),
        }
    }

    fn update_prefilter(
        &mut self,
        payload: Payload,
        state: ConnState,
        _parser: &mut Parser,
    ) -> ConnState {
        if payload.length() == 0 {
            return state;
        }
        log::debug!("updating IntermStream prefilter");
        if payload.from_client {
            self.ctos.append_bytes(payload);
        } else {
            self.stoc.append_bytes(payload);
        }
        state
    }

    fn update_postfilter(
        &mut self,
        payload: Payload,
        state: ConnState,
        subscription: &Subscription<Self::Output>,
    ) -> ConnState {
        if payload.length() == 0 {
            return state;
        }
        log::debug!("updating IntermStream postfilter");
        if payload.from_client {
            if let Some(to_deliver) = self.ctos.append_bytes_chunked(payload) {
                let stream = Stream {
                    five_tuple: self.five_tuple,
                    data: to_deliver,
                    direction: Direction::FromOriginator,
                };
                subscription.invoke(stream);
            }
        } else if let Some(to_deliver) = self.stoc.append_bytes_chunked(payload) {
            let stream = Stream {
                five_tuple: self.five_tuple,
                data: to_deliver,
                direction: Direction::FromResponder,
            };
            subscription.invoke(stream);
        }

        state
    }

    fn on_filter_match(
        &mut self,
        _terminate: bool,
        _parser: &mut Parser,
        subscription: &Subscription<Self::Output>,
    ) -> ConnState {
        // just passed stream filter, deliver all buffered payloads
        log::debug!("Stream filter success.");
        self.deliver_chunked(Direction::FromOriginator, subscription);
        self.deliver_chunked(Direction::FromResponder, subscription);
        ConnState::PostFilterReassembly
    }

    fn on_filter_nomatch(&mut self, _parser: &Parser) -> ConnState {
        ConnState::Remove
    }
}
