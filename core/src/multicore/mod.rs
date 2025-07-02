//! Multicore processing management. 
//!
//! This module provides abstractions for distributing network subscription processing across
//! multiple CPU cores using channel-based message passing. It supports both shared worker pools
//! and dedicated worker pools. 

mod channel_dispatcher;
mod pin;
mod subscription_stats; 
mod dedicated_worker;
mod shared_worker;

pub use channel_dispatcher::{ChannelDispatcher, ChannelMode, Channels};
pub use pin::pin_thread_to_core;
pub use subscription_stats::SubscriptionStats; 
pub use dedicated_worker::DedicatedWorkerThreadSpawner;
pub use shared_worker::SharedWorkerThreadSpawner;

