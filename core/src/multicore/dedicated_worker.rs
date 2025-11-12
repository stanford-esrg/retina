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

/// Spawns worker threads dedicated to a single dispatcher, with all threads using the same handler function.
/// Optimizes for single-receiver scenarios by avoiding select overhead.
pub struct DedicatedWorkerThreadSpawner<T, F>
where
    F: Fn(T) + Send + Sync + 'static,
{
    worker_cores: Option<Vec<CoreId>>,
    dispatcher: Option<Arc<ChannelDispatcher<T>>>,
    handler: Option<F>,
    batch_size: usize,
}

/// Handle for managing a group of dedicated worker threads.
/// Provides methods for graceful shutdown and statistics access.
pub struct DedicatedWorkerHandle<T>
where
    T: Send + 'static,
{
    handles: Vec<JoinHandle<()>>,
    dispatcher: Arc<ChannelDispatcher<T>>,
    shutdown_signal: Arc<AtomicBool>,
}

/// Handle for initializing a group of dedicated worker threads.
impl<T: Send + 'static> DedicatedWorkerThreadSpawner<T, fn(T)> {
    /// Creates a new spawner with a no-op handler function.
    pub fn new() -> Self {
        Self {
            worker_cores: None,
            dispatcher: None,
            handler: Some(|_t: T| {}),
            batch_size: 1,
        }
    }
}

impl<T: Send + 'static> Default for DedicatedWorkerThreadSpawner<T, fn(T)> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: Send + 'static, F> DedicatedWorkerThreadSpawner<T, F>
where
    F: Fn(T) + Send + Sync + Clone + 'static,
{
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

    /// Sets the single dispatcher that all worker threads will process subscriptions from.
    pub fn set_dispatcher(mut self, dispatcher: Arc<ChannelDispatcher<T>>) -> Self {
        self.dispatcher = Some(dispatcher);
        self
    }

    /// Sets the handler function that will process all subscriptions. Changes the function type parameter.
    pub fn set_handler<G>(self, handler: G) -> DedicatedWorkerThreadSpawner<T, G>
    where
        G: Fn(T) + Send + Sync + Clone + 'static,
    {
        DedicatedWorkerThreadSpawner {
            worker_cores: self.worker_cores,
            dispatcher: self.dispatcher,
            handler: Some(handler),
            batch_size: self.batch_size,
        }
    }

    /// Spawns worker threads on configured cores. Returns a handle for managing the worker group.
    /// Uses a barrier to ensure all threads are ready before returning.
    pub fn run(self) -> DedicatedWorkerHandle<T>
    where
        F: 'static,
    {
        let worker_cores = self
            .worker_cores
            .expect("Cores must be set via set_cores()");
        let dispatcher = self
            .dispatcher
            .expect("Dispatcher must be set via set_dispatcher()");
        let handler = Arc::new(
            self.handler
                .expect("Handler function must be set via set_handler()"),
        );

        let batch_size = self.batch_size;
        let receivers = Arc::new(dispatcher.receivers());
        let num_threads = worker_cores.len();
        let shutdown_signal = Arc::new(AtomicBool::new(false));

        // Barrier to ensure all threads are spawned before returning
        let startup_barrier = Arc::new(Barrier::new(num_threads + 1)); // +1 for main thread

        let mut handles = Vec::with_capacity(num_threads);
        for core in worker_cores {
            let receivers_ref = Arc::clone(&receivers);
            let handler_ref = Arc::clone(&handler);
            let dispatcher_ref = Arc::clone(&dispatcher);
            let barrier_ref = Arc::clone(&startup_barrier);
            let shutdown_ref = Arc::clone(&shutdown_signal);

            let handle = thread::spawn(move || {
                if let Err(e) = pin_thread_to_core(core.raw()) {
                    eprintln!("Failed to pin thread to core {core}: {e}");
                }

                // Signal that this thread is ready
                barrier_ref.wait();

                Self::run_worker_loop(
                    &receivers_ref,
                    &handler_ref,
                    &dispatcher_ref,
                    batch_size,
                    &shutdown_ref,
                );
            });

            handles.push(handle);
        }

        // Wait for all threads to be ready
        startup_barrier.wait();

        DedicatedWorkerHandle {
            handles,
            dispatcher,
            shutdown_signal,
        }
    }

    /// Process channel messages in batches.
    fn process_batch(batch: Vec<T>, handler: &F, dispatcher: &Arc<ChannelDispatcher<T>>) {
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
        receivers: &[Arc<Receiver<T>>],
        handler: &F,
        dispatcher: &Arc<ChannelDispatcher<T>>,
        batch_size: usize,
        shutdown_signal: &Arc<AtomicBool>,
    ) {
        let mut select = Select::new();
        for receiver in receivers {
            select.recv(receiver);
        }

        loop {
            if shutdown_signal.load(Ordering::Relaxed) {
                break;
            }

            let oper = select.select();
            let index = oper.index();
            let receiver = &receivers[index];

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
                        break; // Channel is disconnected, exit the loop
                    }
                }
            }
        }
    }
}

impl<T> DedicatedWorkerHandle<T>
where
    T: Send + 'static,
{
    /// Blocks until all queues are empty and no messages are actively processing.
    pub fn wait_for_completion(&self) {
        let receivers = self.dispatcher.receivers();

        loop {
            let queues_empty = receivers.iter().all(|r| r.is_empty());
            let active_handlers = self.dispatcher.stats().get_actively_processing();

            if queues_empty && active_handlers == 0 {
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
    pub fn shutdown(mut self, flush_dir: Option<&PathBuf>) -> SubscriptionStats
    where
        T: Serialize,
    {
        if let Some(dir) = flush_dir {
            self.flush_shutdown(dir);
        } else {
            self.complete_shutdown();
        }

        self.dispatcher.stats().snapshot()
    }

    fn complete_shutdown(&mut self) {
        self.wait_for_completion();
        self.shutdown_signal.store(true, Ordering::SeqCst);

        self.dispatcher.close_channels();

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
        self.shutdown_signal.store(true, Ordering::Relaxed);

        sleep(Duration::from_millis(50));
        let mut flushed_messages = Vec::new();

        for receiver in self.dispatcher.receivers().iter() {
            while let Ok(message) = receiver.try_recv() {
                flushed_messages.push(message);
            }
        }

        let message_count = flushed_messages.len() as u64;
        if message_count == 0 {
            return;
        }

        let file_path = flush_dir.join(format!("{}.json", self.dispatcher.name()));

        if flush_messages(&flushed_messages, &file_path).is_ok() {
            println!(
                "Successfully flushed {message_count} messages to: {}",
                file_path.display()
            );
            self.dispatcher
                .stats()
                .flushed
                .fetch_add(message_count, Ordering::Relaxed);
        } else {
            eprintln!("Error occurred when flushing, dropped {message_count} messages");
            self.dispatcher
                .stats()
                .dropped
                .fetch_add(message_count, Ordering::Relaxed);
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
