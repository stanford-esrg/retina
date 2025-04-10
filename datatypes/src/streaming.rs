/// Infrastructure for managing the state of streaming subscriptions.
/// This should not be accessed directly by the user.

use retina_core::filter::datatypes::Streaming;
use retina_core::conntrack::pdu::L4Pdu;
use crate::Tracked;
use std::time::{Duration, Instant};

/// Callback timer wrapper
pub struct CallbackTimer<T>
where
    T: Tracked
{
    /// The type of counter (time-based, packet-based, or byte-based)
    counter_type: Streaming,
    /// Whether a callback has "unsubscribed" from streaming data
    unsubscribed: bool,
    /// Whether the subscription's filter has matched
    deliverable: bool,
    /// For time-based counters, when the callback was last invoked
    last_invoked: Option<Instant>,
    /// For packet- and byte-based counters, the number of packets/bytes
    /// remaining until the callback will be invoked again.
    /// Can be set to 0 for time-based counters.
    count_remaining: Option<u32>,
    /// TMP - TODO move this into the TrackedWrapper to be shared
    /// TODO - ideally could have multiple tracked datatypes
    data: T
}

impl<T> CallbackTimer<T>
where
    T: Tracked
{
    /// Create a new CallbackTimer with the given counter type and data.
    pub fn new(counter_type: Streaming, first_pkt: &L4Pdu) -> Self {
        Self {
            counter_type,
            unsubscribed: false,
            deliverable: false,
            last_invoked: None,
            count_remaining: None,
            data: T::new(first_pkt),
        }
    }

    /// Clear internal data.
    /// Should be invoked after delivery.
    #[inline]
    pub fn clear(&mut self) {
        self.data.clear();
    }

    #[inline]
    pub fn update(&mut self, pdu: &L4Pdu, reassembled: bool) {
        if !self.unsubscribed {
            self.data.update(pdu, reassembled);
        }
    }

    pub fn stream_protocols() -> Vec<&'static str> {
        T::stream_protocols()
    }

    #[inline]
    pub fn unsubscribe(&mut self) {
        self.unsubscribed = true;
    }

    #[inline]
    pub fn matched(&mut self) {
        if !self.unsubscribed {
            self.deliverable = true;
        }
    }

    /// Check if the callback should be invoked. Update counters.
    pub fn invoke(&mut self, pdu: &L4Pdu) -> bool {
        if self.unsubscribed || !self.deliverable {
            return false;
        }
        match self.counter_type {
            Streaming::Seconds(duration) => {
                // Deliver when first ready for delivery, then every N seconds
                if self.last_invoked.is_none() {
                    self.last_invoked = Some(Instant::now());
                    return true;
                }
                if self.last_invoked.unwrap().elapsed() >= Duration::from_millis((duration * 1000.0).round() as u64) {
                    self.last_invoked = Some(Instant::now());
                    return true;
                }
                false
            }
            Streaming::Packets(count) => {
                // Deliver when first ready for delivery, then every N packets
                if self.count_remaining.is_none() {
                    self.count_remaining = Some(count);
                    return true;
                }
                // New packet received
                let count_remaining = self.count_remaining.unwrap();
                if count_remaining == 1 {
                    self.count_remaining = Some(count);
                    return true;
                }
                self.count_remaining = Some(count_remaining - 1);
                false
            }
            Streaming::Bytes(count) => {
                // Deliver when first ready for delivery, then every N packets
                if self.count_remaining.is_none() {
                    self.count_remaining = Some(count);
                    return true;
                }
                let count_remaining = self.count_remaining.unwrap();
                let len = pdu.mbuf_ref().data_len() as u32;
                if count_remaining <= len {
                    self.count_remaining = Some(count);
                    return true;
                }
                self.count_remaining = Some(count_remaining - len);
                false
            }
        }
    }
}