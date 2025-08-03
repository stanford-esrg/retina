use super::{pin_thread_to_core, ChannelDispatcher, SubscriptionStats};
use crate::CoreId;
use crossbeam::channel::{Receiver, Select};
use std::sync::{atomic::Ordering, Arc, Barrier};
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
}

/// Handle for managing a group of dedicated worker threads.
/// Provides methods for graceful shutdown and statistics access.
pub struct DedicatedWorkerHandle<T>
where
    T: Send + 'static,
{
    handles: Vec<JoinHandle<()>>,
    dispatcher: Arc<ChannelDispatcher<T>>,
}

/// Handle for initializing a group of dedicated worker threads. 
impl<T: Send + 'static> DedicatedWorkerThreadSpawner<T, fn(T)> {
    /// Creates a new spawner with a no-op handler function.
    pub fn new() -> Self {
        Self {
            worker_cores: None,
            dispatcher: None,
            handler: Some(|_t: T| {}),
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

        let receivers = Arc::new(dispatcher.receivers());
        let num_threads = worker_cores.len(); 

        // Barrier to ensure all threads are spawned before returning 
        let startup_barrier = Arc::new(Barrier::new(num_threads + 1)); // +1 for main thread 
        
        let mut handles = Vec::with_capacity(num_threads); 
        for core in worker_cores {
            let receivers_ref = Arc::clone(&receivers);
            let handler_ref = Arc::clone(&handler);
            let dispatcher_ref = Arc::clone(&dispatcher);
            let barrier_ref = Arc::clone(&startup_barrier);

            let handle = thread::spawn(move || {
                if let Err(e) = pin_thread_to_core(core.raw()) {
                    eprintln!("Failed to pin thread to core {}: {}", core, e);
                }

                // Signal that this thread is ready
                barrier_ref.wait();

                Self::run_worker_loop(&receivers_ref, &handler_ref, &dispatcher_ref);
            });

            handles.push(handle); 
        }

        // Wait for all threads to be ready
        startup_barrier.wait(); 

        return DedicatedWorkerHandle {
            handles, 
            dispatcher
        }
    }

    /// Main worker loop that uses crossbeam Select to efficiently wait on multiple channels.
    /// Routes each subscription to the appropriate handler and updates processing statistics.
    fn run_worker_loop(
        receivers: &[Arc<Receiver<T>>],
        handler: &F,
        dispatcher: &Arc<ChannelDispatcher<T>>,
    ) {
        let mut select = Select::new();
        for receiver in receivers {
            select.recv(receiver);
        }

        loop {
            let oper = select.select();
            let index = oper.index();
            match oper.recv(&receivers[index]) {
                Ok(data) => {
                    dispatcher
                        .stats()
                        .actively_processing
                        .fetch_add(1, Ordering::Relaxed);
                    handler(data);
                    dispatcher.stats().processed.fetch_add(1, Ordering::Relaxed);
                    dispatcher
                        .stats()
                        .actively_processing
                        .fetch_sub(1, Ordering::Relaxed);
                }
                Err(_) => {
                    break;
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
    /// Returns the final statistics snapshot
    pub fn shutdown(mut self) -> SubscriptionStats {
        // Wait for active processing to complete
        self.wait_for_completion();
        let final_stats = self.dispatcher.stats().snapshot();
        
        // Drop channels to break out of processing loops 
        self.dispatcher.close_channels();
        
        // Drop the dispatcher
        drop(self.dispatcher);

        // Wait for all worker threads to complete
        for (i, handle) in self.handles.drain(..).enumerate() {
            if let Err(e) = handle.join() {
                eprintln!("Thread {} error: {:?}", i, e);
            }
        }
        
        return final_stats; 
    }
}