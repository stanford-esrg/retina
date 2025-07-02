//! Statistics tracking for subscription processing.
//!
//! This module provides thread-safe statistics tracking allowing monitoring of subscription dispatch, processing, and completion states.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::thread::sleep;
use std::time;

use crossbeam::channel::Receiver;

/// Thread-safe statistics tracker for the various stages of subscription processing.
/// All counters use atomic operations for thread safety.
#[derive(Default)]
pub struct SubscriptionStats {
    /// Number of messages dispatched to processing queues.
    pub dispatched: AtomicU64,

    /// Number of messages dropped due to queue overflow or errors.
    pub dropped: AtomicU64,

    /// Number of messages that have completed processing.
    /// Wrapped in `Arc` for thread sharing.
    pub processed: Arc<AtomicU64>,

    /// Number of messages currently being processed.
    /// Wrapped in `Arc` for thread sharing.
    pub actively_processing: Arc<AtomicU64>,
}

impl SubscriptionStats {
    /// Creates a new instance with all counters initialized to zero.
    pub fn new() -> Self {
        Self {
            dispatched: AtomicU64::new(0),
            dropped: AtomicU64::new(0),
            processed: Arc::new(AtomicU64::new(0)),
            actively_processing: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Returns the current number of dispatched messages.
    pub fn get_dispatched(&self) -> u64 {
        self.dispatched.load(Ordering::Relaxed)
    }

    /// Returns the current number of dropped messages.
    pub fn get_dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    /// Returns the current number of processed messages.
    pub fn get_processed(&self) -> u64 {
        self.processed.load(Ordering::Relaxed)
    }

    /// Returns the current number of messages actively being processed.
    pub fn get_actively_processing(&self) -> u64 {
        self.actively_processing.load(Ordering::Relaxed)
    }

    /// Blocks until all queues are empty and no messages are actively processing.
    pub fn waiting_completion<T>(&self, receivers: Vec<Arc<Receiver<T>>>) {
        loop {
            let queues_empty = receivers.iter().all(|r| r.is_empty());
            let active_handlers = self.get_actively_processing();

            if queues_empty && active_handlers == 0 {
                break;
            }

            // Small sleep to avoid busy waiting
            sleep(time::Duration::from_millis(10));
        }
    }

    /// Prints current statistics to stdout.
    pub fn print(&self) {
        println!("Dispatched: {}", self.get_dispatched());
        println!("Dropped: {}", self.get_dropped());
        println!("Processed: {}", self.get_processed());
    }
}
