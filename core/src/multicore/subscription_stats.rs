use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::thread::sleep; 
use std::time; 

use crossbeam::channel::Receiver; 

#[derive(Default)]
pub struct SubscriptionStats {
    pub dispatched: AtomicU64,
    pub dropped: AtomicU64,
    pub processed: Arc<AtomicU64>,
    pub actively_processing: Arc<AtomicU64> 
}

impl SubscriptionStats {
    pub fn new() -> Self {
        Self {
            dispatched: AtomicU64::new(0),
            dropped: AtomicU64::new(0),
            processed: Arc::new(AtomicU64::new(0)),
            actively_processing: Arc::new(AtomicU64::new(0))
        }
    }

    pub fn get_dispatched(&self) -> u64 {
        self.dispatched.load(Ordering::Relaxed)
    }

    pub fn get_dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    pub fn get_processed(&self) -> u64 {
        self.processed.load(Ordering::Relaxed)
    }

    pub fn get_actively_processing(&self) -> u64 {
        self.actively_processing.load(Ordering::Relaxed) 
    }

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

    pub fn print(&self) {
        println!("Dispatched: {}", self.get_dispatched());
        println!("Dropped: {}", self.get_dropped());
        println!("Processed: {}", self.get_processed());
    }
}
