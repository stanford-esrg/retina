use super::{pin_thread_to_core, ChannelDispatcher, SubscriptionStats};
use crate::CoreId;
use crossbeam::channel::{Receiver, Select, TryRecvError};
use std::sync::{atomic::Ordering, Arc, Barrier};
use std::thread::{self, sleep, JoinHandle};
use std::time::Duration;

/// Spawns worker threads that share multiple dispatchers, with each thread handling subscriptions
/// from all configured dispatchers using different handlers per dispatcher type.
pub struct SharedWorkerThreadSpawner<T>
where
    T: Send + 'static,
{
    worker_cores: Option<Vec<CoreId>>,
    dispatchers: Vec<Arc<ChannelDispatcher<T>>>,
    handlers: Vec<Box<dyn Fn(T) + Send + Sync>>,
    batch_size: usize,
}

/// Handle for managing a group of shared worker threads.
/// Provides methods for graceful shutdown and statistics access.
pub struct SharedWorkerHandle<T>
where
    T: Send + 'static,
{
    handles: Vec<JoinHandle<()>>,
    dispatchers: Vec<Arc<ChannelDispatcher<T>>>,
}

/// Handle for initializing a group of shared worker threads.
impl<T> SharedWorkerThreadSpawner<T>
where
    T: Send + Clone + 'static,
{
    /// Creates a new spawner with no cores, dispatchers, or handlers configured.
    pub fn new() -> Self {
        Self {
            worker_cores: None,
            dispatchers: Vec::new(),
            handlers: Vec::new(),
            batch_size: 1,
        }
    }

    /// Sets the CPU cores that worker threads will be pinned to.
    pub fn set_cores(mut self, cores: Vec<CoreId>) -> Self {
        self.worker_cores = Some(cores);
        self
    }

    /// Sets the batch size for processing messages.
    pub fn set_batch_size(mut self, batch_size: usize) -> Self {
        self.batch_size = batch_size.max(1);
        self
    }

    /// Adds a dispatcher-handler pair. Each dispatcher's subscriptions will be processed by its corresponding handler.
    pub fn add_dispatcher<F>(mut self, dispatcher: Arc<ChannelDispatcher<T>>, handler: F) -> Self
    where
        F: Fn(T) + Send + Sync + 'static,
    {
        self.dispatchers.push(dispatcher);
        self.handlers.push(Box::new(handler));
        self
    }

    /// Builds a flattened list of all receivers tagged with their dispatcher index.
    /// This allows workers to know which handler to use for each received subscription.
    fn build_tagged_receivers(&self) -> Vec<(usize, Arc<Receiver<T>>)> {
        let mut tagged_receivers = Vec::new();

        for (index, dispatcher) in self.dispatchers.iter().enumerate() {
            let receivers = dispatcher.receivers();
            for receiver in receivers {
                tagged_receivers.push((index, receiver));
            }
        }

        tagged_receivers
    }

    /// Spawns worker threads on the configured cores. Each thread processes subscriptions
    /// from all dispatchers using a select operation to handle whichever channel has data available.
    /// Returns a handle for managing the worker group and uses a barrier to ensure all threads are ready.
    pub fn run(self) -> SharedWorkerHandle<T> {
        let tagged_receivers = Arc::new(self.build_tagged_receivers());
        let handlers = Arc::new(self.handlers);
        let dispatchers = Arc::new(self.dispatchers);
        let batch_size = self.batch_size;
        let worker_cores = self
            .worker_cores
            .expect("Cores must be set via set_cores()");

        let num_threads = worker_cores.len();

        // Barrier to ensure all threads are spawned before returning
        let startup_barrier = Arc::new(Barrier::new(num_threads + 1)); // +1 for main thread

        let mut handles = Vec::with_capacity(num_threads);
        for core in worker_cores {
            let tagged_receivers_ref = Arc::clone(&tagged_receivers);
            let handlers_ref = Arc::clone(&handlers);
            let dispatchers_ref = dispatchers.clone();
            let barrier_ref = Arc::clone(&startup_barrier);

            let handle = thread::spawn(move || {
                if let Err(e) = pin_thread_to_core(core.raw()) {
                    eprintln!("Failed to pin thread to core {core}: {e}");
                }

                // Signal that this thread is ready
                barrier_ref.wait();

                Self::run_worker_loop(
                    &tagged_receivers_ref,
                    &handlers_ref,
                    &dispatchers_ref,
                    batch_size,
                );
            });

            handles.push(handle);
        }

        // Wait for all threads to be ready
        startup_barrier.wait();

        SharedWorkerHandle {
            handles,
            dispatchers: dispatchers.to_vec(),
        }
    }

    /// Process channel messages in batches.
    fn process_batch(
        batch: Vec<T>,
        handler: &(dyn Fn(T) + Send + Sync),
        dispatcher: &Arc<ChannelDispatcher<T>>,
    ) {
        if batch.is_empty() {
            return;
        }

        let batch_size = batch.len() as u64;

        dispatcher
            .stats()
            .actively_processing
            .fetch_add(batch_size, Ordering::Relaxed);

        for data in batch {
            handler(data);
        }

        dispatcher
            .stats()
            .processed
            .fetch_add(batch_size, Ordering::Relaxed);
        dispatcher
            .stats()
            .actively_processing
            .fetch_sub(batch_size, Ordering::Relaxed);
    }

    /// Main worker loop that uses crossbeam Select to efficiently wait on multiple channels.
    /// Routes each subscription to the appropriate handler and updates processing statistics.
    fn run_worker_loop(
        tagged_receivers: &[(usize, Arc<Receiver<T>>)],
        handlers: &[Box<dyn Fn(T) + Send + Sync>],
        dispatchers: &[Arc<ChannelDispatcher<T>>],
        batch_size: usize,
    ) {
        let mut select = Select::new();
        for (_, receiver) in tagged_receivers.iter() {
            select.recv(receiver);
        }

        loop {
            let oper = select.select();
            let oper_index = oper.index();
            let (handler_index, receiver) = &tagged_receivers[oper_index];
            let handler = &handlers[*handler_index];
            let dispatcher = &dispatchers[*handler_index];

            let mut batch = Vec::with_capacity(batch_size);
            let mut recv_error: Option<TryRecvError> = None;

            match oper.recv(receiver) {
                Ok(msg) => {
                    batch.push(msg);
                }
                Err(_) => {
                    // Channel is disconnected, exit the loop
                    break;
                }
            }

            for _ in 0..batch_size {
                match receiver.try_recv() {
                    Ok(msg) => {
                        batch.push(msg);
                    }
                    Err(e) => {
                        recv_error = Some(e);
                        break;
                    }
                }
            }

            if !batch.is_empty() {
                Self::process_batch(batch, handler, dispatcher);
            }

            if let Some(err) = recv_error {
                match err {
                    TryRecvError::Empty => {
                        continue; // Channel is empty, go back to select
                    }
                    TryRecvError::Disconnected => {
                        break; // Channel closed, exit the loop
                    }
                }
            }
        }
    }
}

impl<T> Default for SharedWorkerThreadSpawner<T>
where
    T: Send + Clone + 'static,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<T> SharedWorkerHandle<T>
where
    T: Send + 'static,
{
    /// Blocks until all queues are empty and no messages are actively processing.
    pub fn wait_for_completion(&self) {
        loop {
            let all_complete = self.dispatchers.iter().all(|dispatcher| {
                let receivers = dispatcher.receivers();
                let queues_empty = receivers.iter().all(|r| r.is_empty());
                let active_handlers = dispatcher.stats().get_actively_processing();

                queues_empty && active_handlers == 0
            });

            if all_complete {
                break;
            }

            // Small sleep to avoid busy waiting
            sleep(Duration::from_millis(10));
        }
    }

    /// Gracefully shuts down all worker threads.
    /// Returns the final statistics snapshot
    pub fn shutdown(mut self) -> Vec<SubscriptionStats> {
        // Wait for active processing to complete
        self.wait_for_completion();
        let final_stats: Vec<SubscriptionStats> = self
            .dispatchers
            .iter()
            .map(|dispatcher| dispatcher.stats().snapshot())
            .collect();

        // Drop channels to break out of processing loops
        for dispatcher in &self.dispatchers {
            dispatcher.close_channels();
        }

        // Wait for all worker threads to complete
        for (i, handle) in self.handles.drain(..).enumerate() {
            if let Err(e) = handle.join() {
                eprintln!("Thread {i} error: {e:?}");
            }
        }

        final_stats
    }
}
