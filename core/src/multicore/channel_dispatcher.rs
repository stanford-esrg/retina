//! Channel Dispatcher
//!
//! This module provides a channel dispatching system that operate in two modes:
//! - **Shared**: All data is sent through a single shared channel.
//! - **PerCore**: Data is dispatched to specific channels based on coreID
//!
//! The dispatcher automatically tracks statistics for dispatched and dropped subscriptions
//! and provides thread-safe access to receivers for consumption.

use super::SubscriptionStats;
use crate::CoreId;
use crossbeam::channel::{bounded, Receiver, Sender, TrySendError};
use std::collections::HashMap;
use std::sync::{atomic::Ordering, Arc, Mutex};
use thiserror::Error;

/// Defines the operating mode for the channel dispatcher.
///
/// # Examples
///
/// ```rust
/// // Create a shared mode dispatcher
/// let shared_mode = ChannelMode::Shared;
/// ```
///
/// ```rust
/// // Create a per-core mode dispatcher for specific cores
/// let cores = vec![CoreId(0), CoreId(1), CoreId(2)];
/// let per_core_mode = ChannelMode::PerCore(cores);
/// ```
#[derive(Clone)]
pub enum ChannelMode {
    /// All subscriptions are sent through a single shared channel.
    Shared,
    /// Messages are routed to specific channels based on core ID.
    PerCore(Vec<CoreId>),
}

type Channel<T> = (Option<Sender<T>>, Arc<Receiver<T>>); 

/// Internal representation of the channel configuration based on chosen operating mode.
pub enum Channels<T> {
    /// Single shared sender and receiver pair.
    Shared(Channel<T>),
    /// HashMap mapping core IDs to their dedicated sender/receiver pairs.
    PerCore(HashMap<CoreId, Channel<T>>),
}

/// A unified thread-safe interface for dispatching subscriptions.
///
/// # Type Parameters
///
/// * `T` - The type of subscriptions being dispatched. Must implement `Send + 'static`.
pub struct ChannelDispatcher<T> {
    channels: Mutex<Channels<T>>,
    stats: SubscriptionStats,
}

impl<T: Send + 'static> ChannelDispatcher<T> {
    /// Creates a new channel dispatcher with the specified mode and channel capacity.
    pub fn new(mode: ChannelMode, channel_size: usize) -> Self {
        match mode {
            ChannelMode::Shared => Self::new_shared(channel_size),
            ChannelMode::PerCore(rx_cores) => Self::new_percore(&rx_cores, channel_size),
        }
    }

    /// Creates a new shared-mode dispatcher.
    fn new_shared(channel_size: usize) -> Self {
        let (tx, rx) = bounded(channel_size);

        Self {
            channels: Mutex::new(Channels::Shared((Some(tx), Arc::new(rx)))),
            stats: SubscriptionStats::new(),
        }
    }

    /// Creates a new per-core mode dispatcher.
    fn new_percore(rx_cores: &[CoreId], channel_size: usize) -> Self {
        let mut map = HashMap::with_capacity(rx_cores.len());

        for &core in rx_cores {
            let (tx, rx) = bounded(channel_size);
            map.insert(core, (Some(tx), Arc::new(rx)));
        }

        Self {
            channels: Mutex::new(Channels::PerCore(map)),
            stats: SubscriptionStats::new(),
        }
    }

    /// Dispatches data to appropriate channel based on the dispatcher's mode.
    ///
    /// In either case, the subscription passing is non-blocking through crossbeam's try_send
    /// operation and doesn't rely on mutexes internally (relies on lower-level atomic operations).
    pub fn dispatch(&self, data: T, core_id: Option<&CoreId>) -> Result<(), DispatchError<T>> {
        let channels = self.channels.lock().unwrap();

        let result = match &*channels {
            Channels::PerCore(map) => {
                let core = core_id.ok_or(DispatchError::CoreIdRequired)?;
                let (sender_result, _) = map.get(core).ok_or(DispatchError::CoreNotFound(*core))?;
                match sender_result {
                    Some(sender) => sender.try_send(data),
                    None => Err(TrySendError::Disconnected(data)),
                }
            }
            Channels::Shared((sender_result, _)) => match sender_result {
                Some(sender) => sender.try_send(data),
                None => Err(TrySendError::Disconnected(data)),
            },
        };

        match result {
            Ok(()) => {
                self.stats.dispatched.fetch_add(1, Ordering::Relaxed);
                Ok(())
            }
            Err(e) => {
                self.stats.dropped.fetch_add(1, Ordering::Relaxed);
                Err(DispatchError::SendFailed(e))
            }
        }
    }

    /// Returns a vector of all receivers for subscription consumption.
    pub fn receivers(&self) -> Vec<Arc<Receiver<T>>> {
        let channels = self.channels.lock().unwrap();

        match &*channels {
            Channels::PerCore(map) => map.values().map(|(_, rx)| Arc::clone(rx)).collect(),
            Channels::Shared((_, rx)) => vec![Arc::clone(rx)],
        }
    }

    /// Manually closes all channels.
    pub fn close_channels(&self) {
        let mut channels = self.channels.lock().unwrap();

        match &mut *channels {
            Channels::PerCore(map) => {
                for (_, (sender_result, _)) in map.iter_mut() {
                    *sender_result = None;
                }
            }
            Channels::Shared((sender_result, _)) => {
                *sender_result = None;
            }
        }
    }

    /// Returns a reference to the dispatch statistics.
    pub fn stats(&self) -> &SubscriptionStats {
        &self.stats
    }
}

/// Errors that can occur during message dispatch.
#[derive(Debug, Error)]
pub enum DispatchError<T> {
    /// A core ID was required for PerCore mode dispatch but none was provided.
    #[error("Core ID required for PerCore dispatch")]
    CoreIdRequired,

    /// The specified core ID doesn't have a configured channel.
    ///
    /// This error occurs when the core ID provided for dispatch wasn't included in the original
    /// core list when created the PerCore dispatcher.
    #[error("No sender found for core: {0}")]
    CoreNotFound(CoreId),

    /// The underlying channel send operation failed.
    ///
    /// This error wraps the `TrySendError` from the crossbeam channel, which can occur when:
    /// - The channel is full (`TrySendError::Full`)
    /// - All receivers have been dropped (`TrySendError::Disconnected`)
    #[error("Failed to send data")]
    SendFailed(#[from] TrySendError<T>),
}
