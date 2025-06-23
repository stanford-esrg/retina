use std::sync::Arc;
use std::thread;
use crossbeam::channel::{Select, Receiver};
use crate::{ChannelDispatcher, pin_thread_to_core};

pub struct DedicatedWorkerThreadSpawner<T, F> 
where
    F: Fn(T) + Send + Sync + 'static,
{
    worker_cores: Option<Vec<usize>>,
    dispatcher: Option<Arc<ChannelDispatcher<T>>>,
    thread_fn: Option<F>,
}

impl<T: Send + 'static> DedicatedWorkerThreadSpawner<T, fn(T)> {
    pub fn new() -> Self {
        DedicatedWorkerThreadSpawner {
            worker_cores: None,
            dispatcher: None,
            thread_fn: Some(|_t: T| {}),
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
    pub fn set_cores(mut self, cores: Vec<usize>) -> Self {
        self.worker_cores = Some(cores);
        self
    }

    pub fn set_dispatcher(mut self, dispatcher: Arc<ChannelDispatcher<T>>) -> Self {
        self.dispatcher = Some(dispatcher);
        self
    }

    pub fn set<G>(self, func: G) -> DedicatedWorkerThreadSpawner<T, G>
    where
        G: Fn(T) + Send + Sync + Clone + 'static,
    {
        DedicatedWorkerThreadSpawner {
            worker_cores: self.worker_cores,
            dispatcher: self.dispatcher,
            thread_fn: Some(func),
        }
    }
    
    pub fn run(self)
    where
        F: 'static,
    {
        let worker_cores = self.worker_cores.expect("Cores must be set via set_cores()");
        let dispatcher = self.dispatcher.expect("Dispatcher must be set via set_dispatcher()");
        let thread_fn = Arc::new(self.thread_fn.expect("Thread function must be set via set()"));
        let receivers = Arc::new(dispatcher.receivers());

        let single_receiver = receivers.len() == 1; 

        for core in worker_cores {
            let receivers_ref = Arc::clone(&receivers);
            let thread_fn_ref = Arc::clone(&thread_fn);
            
            thread::spawn(move || {
                if let Err(e) = pin_thread_to_core(core) {
                    eprintln!("Failed to pin thread to core {}: {}", core, e);
                }
                
                // Optimize for single receiver case
                if single_receiver {
                    Self::handle_single_receiver(&receivers_ref[0], &thread_fn_ref);
                } else {
                    Self::handle_multiple_receivers(&receivers_clone_ref, &thread_fn_ref);
                }
            });
        }
    }

    fn handle_single_receiver(receiver: &Arc<Receiver<T>>, thread_fn: &F) {
        while let Ok(data) = receiver.recv() {
            thread_fn(data);
        }
    }

    fn handle_multiple_receivers(receivers: &[Arc<Receiver<T>>], thread_fn: &F) {
        let mut select = Select::new();
        for receiver in receivers {
            select.recv(receiver);
        }

        loop {
            let oper = select.select();
            let index = oper.index();
            match oper.recv(&receivers[index]) {
                Ok(data) => thread_fn(data),
                Err(_) => break,
            }
        }
    }    
}
