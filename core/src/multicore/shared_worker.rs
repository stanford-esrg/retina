use super::{pin_thread_to_core, ChannelDispatcher, SubscriptionStats};
use crate::CoreId;
use crossbeam::channel::{Receiver, Select, TryRecvError};
use serde::Serialize;
use std::fs::File;
use std::io::{Error, Result, Write};
use std::path::{Path, PathBuf};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Barrier,
};
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
    shutdown_signal: Arc<AtomicBool>,
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
        let shutdown_signal = Arc::new(AtomicBool::new(false));

        // Barrier to ensure all threads are spawned before returning
        let startup_barrier = Arc::new(Barrier::new(num_threads + 1)); // +1 for main thread

        let mut handles = Vec::with_capacity(num_threads);
        for core in worker_cores {
            let tagged_receivers_ref = Arc::clone(&tagged_receivers);
            let handlers_ref = Arc::clone(&handlers);
            let dispatchers_ref = dispatchers.clone();
            let barrier_ref = Arc::clone(&startup_barrier);
            let shutdown_ref = Arc::clone(&shutdown_signal);

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
                    &shutdown_ref,
                );
            });

            handles.push(handle);
        }

        // Wait for all threads to be ready
        startup_barrier.wait();

        SharedWorkerHandle {
            handles,
            dispatchers: dispatchers.to_vec(),
            shutdown_signal,
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
        shutdown_signal: &Arc<AtomicBool>,
    ) {
        let mut select = Select::new();
        for (_, receiver) in tagged_receivers.iter() {
            select.recv(receiver);
        }

        loop {
            if shutdown_signal.load(Ordering::Relaxed) {
                break;
            }

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
                Self::process_batch(batch, handler.as_ref(), dispatcher);
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
    /// If `flush_dir` is provided, all channel contents are flushed to disk.
    /// Otherwise, it waits for every item in the channels to be processed.
    /// In the non-flush case, this may appear to stall, since the
    /// function blocks until all pending work is completed. Returns
    /// the final statistics snapshot.
    pub fn shutdown(mut self, flush_dir: Option<&PathBuf>) -> Vec<SubscriptionStats>
    where
        T: Serialize,
    {
        if let Some(dir) = flush_dir {
            self.flush_shutdown(dir);
        } else {
            self.complete_shutdown();
        }

        self.dispatchers
            .iter()
            .map(|dispatcher| dispatcher.stats().snapshot())
            .collect()
    }

    fn complete_shutdown(&mut self) {
        self.wait_for_completion();
        self.shutdown_signal.store(true, Ordering::SeqCst);

        for dispatcher in &self.dispatchers {
            dispatcher.close_channels();
        }

        for (i, handle) in self.handles.drain(..).enumerate() {
            if let Err(e) = handle.join() {
                eprintln!("Thread {i} error: {e:?}");
            }
        }
    }

    fn flush_shutdown(&mut self, flush_dir: &Path)
    where
        T: Serialize,
    {
        self.shutdown_signal.store(true, Ordering::SeqCst);

        for dispatcher in &self.dispatchers {
            dispatcher.close_channels();
        }

        for (i, handle) in self.handles.drain(..).enumerate() {
            if let Err(e) = handle.join() {
                eprintln!("Thread {i} error: {e:?}");
            }
        }

        for (i, dispatcher) in self.dispatchers.iter().enumerate() {
            let mut flushed_messages = Vec::new();

            let receivers = dispatcher.receivers();
            for receiver in receivers.iter() {
                while let Ok(message) = receiver.try_recv() {
                    flushed_messages.push(message);
                }
            }

            let message_count = flushed_messages.len() as u64;
            if message_count == 0 {
                continue;
            }

            let file_path = flush_dir.join(format!("{}.json", dispatcher.name()));

            if flush_messages(&flushed_messages, &file_path).is_ok() {
                println!(
                    "Dispatcher {i}: flushed {message_count} messages to {}",
                    file_path.display()
                );
                dispatcher
                    .stats()
                    .flushed
                    .fetch_add(message_count, Ordering::Relaxed);
            } else {
                eprintln!("Dispatcher {i}: error flushing, dropped {message_count} messages");
                dispatcher
                    .stats()
                    .dropped
                    .fetch_add(message_count, Ordering::Relaxed);
            }
        }
    }
}

/// Writes messages to disk as formatted JSON.
fn flush_messages<T: Serialize>(messages: &[T], path: &PathBuf) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let mut file = File::create(path)?;
    let json_str = serde_json::to_string_pretty(messages).map_err(Error::other)?;
    writeln!(file, "{json_str}")?;
    Ok(())
}
