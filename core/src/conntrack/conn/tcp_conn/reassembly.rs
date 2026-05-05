use crate::conntrack::conn::conn_info::{ConnInfo, ConnState};
use crate::conntrack::pdu::L4Pdu;
use crate::protocols::packet::tcp::{ACK, FIN, RST, SYN};
use crate::protocols::stream::ParserRegistry;
use crate::subscription::{Subscription, Trackable};

use anyhow::{bail, Result};
use std::collections::VecDeque;

/// Represents a uni-directional TCP flow
#[derive(Debug)]
pub(crate) struct TcpFlow {
    /// Expected sequence number of next segment
    pub(super) next_seq: Option<u32>,
    /// Flow status for consumed control packets.
    /// Matches TCP flag bits.
    pub(super) consumed_flags: u8,
    /// Out-of-order buffer
    pub(crate) ooo_buf: OutOfOrderBuffer,
}

impl TcpFlow {
    /// Creates a default TCP flow
    #[inline]
    pub(super) fn default(capacity: usize) -> Self {
        TcpFlow {
            next_seq: None,
            consumed_flags: 0,
            ooo_buf: OutOfOrderBuffer::new(capacity),
        }
    }

    /// Creates a new TCP flow with given next sequence number, flags,
    /// and out-of-order buffer
    #[inline]
    pub(super) fn new(capacity: usize, next_seq: u32, flags: u8) -> Self {
        TcpFlow {
            next_seq: Some(next_seq),
            consumed_flags: flags,
            ooo_buf: OutOfOrderBuffer::new(capacity),
        }
    }

    /// Attempt to insert incoming data segment into flow.
    /// Buffer future segments and drop old segments.
    /// Shunts TcpStream if the incoming segment causes out-of-order buffer overflow
    #[inline]
    pub(super) fn insert_segment<T: Trackable>(
        &mut self,
        mut segment: L4Pdu,
        info: &mut ConnInfo<T>,
        subscription: &Subscription<T::Subscribed>,
        registry: &ParserRegistry,
    ) {
        let length = segment.length() as u32;
        let cur_seq = segment.seq_no();

        if let Some(next_seq) = self.next_seq {
            if next_seq == cur_seq {
                // Segment is the next expected segment in the sequence
                self.consumed_flags |= segment.flags();
                if segment.flags() & RST != 0 {
                    info.consume_pdu(segment, subscription, registry);
                    return;
                }
                let mut expected_seq = cur_seq.wrapping_add(length);
                if segment.flags() & FIN != 0 {
                    expected_seq = cur_seq.wrapping_add(1);
                }
                info.consume_pdu(segment, subscription, registry);
                self.flush_ooo_buffer::<T>(expected_seq, info, subscription, registry);
            } else if wrapping_lt(next_seq, cur_seq) {
                // Segment comes after the next expected segment
                self.buffer_ooo_seg(segment, info);
            } else if let Some(expected_seq) = overlap(&mut segment, next_seq) {
                // Segment starts before the next expected segment but has new data
                self.consumed_flags |= segment.flags();
                info.consume_pdu(segment, subscription, registry);
                self.flush_ooo_buffer::<T>(expected_seq, info, subscription, registry);
            } else {
                // Segment contains old data
                log::debug!(
                    "Dropping old segment. cur: {} expect: {}",
                    cur_seq,
                    next_seq
                );
                drop(segment);
            }
        } else {
            // expecting SYNACK in response to the originator's SYN
            if segment.flags() & (SYN | ACK) != 0 {
                let expected_seq = cur_seq.wrapping_add(1 + length);
                self.next_seq = Some(expected_seq);
                self.consumed_flags |= segment.flags();
                info.consume_pdu(segment, subscription, registry);
                self.flush_ooo_buffer::<T>(expected_seq, info, subscription, registry);
            } else {
                // Buffer out-of-order non-SYNACK packets
                self.buffer_ooo_seg(segment, info);
            }
        }
    }

    /// Insert packet into ooo buffer and handle overflow
    #[inline]
    fn buffer_ooo_seg<T: Trackable>(&mut self, segment: L4Pdu, info: &mut ConnInfo<T>) {
        if self.ooo_buf.insert_back(segment).is_err() {
            log::warn!("Out-of-order buffer overflow");
            info.state = ConnState::Remove;
        }
    }

    /// Flushes the flow's out-of-order buffer given the next expected
    /// sequence number and updates the flow's new next expected
    /// sequence number and status after the flush.
    #[inline]
    pub(super) fn flush_ooo_buffer<T: Trackable>(
        &mut self,
        expected_seq: u32,
        info: &mut ConnInfo<T>,
        subscription: &Subscription<T::Subscribed>,
        registry: &ParserRegistry,
    ) {
        if info.state == ConnState::Remove {
            return;
        }
        let next_seq = self.ooo_buf.flush_ordered::<T>(
            expected_seq,
            &mut self.consumed_flags,
            info,
            subscription,
            registry,
        );
        self.next_seq = Some(next_seq);
    }
}

/// A buffer to hold reordered TCP segments
#[derive(Debug)]
pub(crate) struct OutOfOrderBuffer {
    capacity: usize,
    pub(crate) buf: VecDeque<L4Pdu>,
}

impl OutOfOrderBuffer {
    /// Creates a new OutOfOrderBuffer with capacity
    fn new(capacity: usize) -> Self {
        OutOfOrderBuffer {
            capacity,
            buf: VecDeque::new(),
        }
    }

    /// Returns the number of elements in the buffer
    pub(crate) fn len(&self) -> usize {
        self.buf.len()
    }

    /// Inserts segment at the end of the buffer.
    fn insert_back(&mut self, segment: L4Pdu) -> Result<()> {
        log::debug!("insert with seq : {:#?}", segment.seq_no());
        if self.len() >= self.capacity {
            // // must clear to drop buffered Mbufs
            // self.buf.clear();
            bail!("Out-of-order buffer overflow.");
        }
        self.buf.push_back(segment);
        Ok(())
    }

    /// Consumes segments with expected data, retains segments with future data,
    /// and drops segments with old data.
    /// Returns the next expected sequence number and control flags of consumed segments.
    #[inline]
    fn flush_ordered<T: Trackable>(
        &mut self,
        expected_seq: u32,
        consumed_flags: &mut u8,
        info: &mut ConnInfo<T>,
        subscription: &Subscription<T::Subscribed>,
        registry: &ParserRegistry,
    ) -> u32 {
        let mut next_seq = expected_seq;
        let mut index = 0;
        while index < self.len() {
            if info.state == ConnState::Remove {
                return next_seq;
            }

            // unwraps ok because index < len
            let cur_seq = self.buf.get_mut(index).unwrap().seq_no();
            log::debug!("Flushing...current seq: {:#?}", cur_seq);

            if next_seq == cur_seq {
                let segment = self.buf.remove(index).unwrap();
                *consumed_flags |= segment.flags();
                if segment.flags() & RST != 0 {
                    info.consume_pdu(segment, subscription, registry);
                    return next_seq;
                }
                next_seq = next_seq.wrapping_add(segment.length() as u32);
                if segment.flags() & FIN != 0 {
                    next_seq = next_seq.wrapping_add(1);
                }
                info.consume_pdu(segment, subscription, registry);
                index = 0;
            } else if wrapping_lt(next_seq, cur_seq) {
                index += 1;
            } else {
                let mut segment = self.buf.remove(index).unwrap();
                if let Some(update_seq) = overlap(&mut segment, next_seq) {
                    next_seq = update_seq;
                    *consumed_flags |= segment.flags();
                    info.consume_pdu(segment, subscription, registry);
                    index = 0;
                } else {
                    log::debug!("Dropping old segment during flush.");
                    drop(segment);
                    index += 1;
                }
            }
        }
        next_seq
    }
}

pub(crate) fn wrapping_lt(lhs: u32, rhs: u32) -> bool {
    // From RFC1323:
    //     TCP determines if a data segment is "old" or "new" by testing
    //     whether its sequence number is within 2**31 bytes of the left edge
    //     of the window, and if it is not, discarding the data as "old".  To
    //     insure that new data is never mistakenly considered old and vice-
    //     versa, the left edge of the sender's window has to be at most
    //     2**31 away from the right edge of the receiver's window.
    lhs.wrapping_sub(rhs) > (1 << 31)
}

/// Check if a segment has overlapping data with the received bytes.
/// Returns the new expected sequence number if there is overlap
fn overlap(segment: &mut L4Pdu, expected_seq: u32) -> Option<u32> {
    let length = segment.length();
    let cur_seq = segment.seq_no();
    let end_seq = cur_seq.wrapping_add(length as u32);

    if wrapping_lt(expected_seq, end_seq) {
        // contains new data
        let new_data_len = end_seq.wrapping_sub(expected_seq);
        let overlap_data_len = expected_seq.wrapping_sub(cur_seq);

        log::debug!("Overlap with new data size : {:#?}", new_data_len);
        segment.ctxt.offset += overlap_data_len as usize;
        segment.ctxt.length = new_data_len as usize;
        Some(end_seq)
    } else {
        None
    }
}
