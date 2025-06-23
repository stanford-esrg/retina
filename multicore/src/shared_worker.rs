use std::sync::Arc;
use std::thread;
use crossbeam::channel::{Select, Receiver};
use crate::{ChannelDispatcher, pin_thread_to_core};

pub struct SharedWorkerThreadSpawner<T>
where
    T: Send + 'static,
{
    worker_cores: Option<Vec<usize>>,
    dispatchers: Vec<Arc<ChannelDispatcher<T>>>,
    handlers: Vec<Box<dyn Fn(T) + Send + Sync>>,
}

impl<T> SharedWorkerThreadSpawner<T>
where
    T: Send + Clone + 'static,
{
    pub fn new() -> Self {
        Self {
            worker_cores: None,
            dispatchers: Vec::new(),
            handlers: Vec::new(),
        }
    }

    pub fn set_cores(mut self, cores: Vec<usize>) -> Self {
        self.worker_cores = Some(cores);
        self
    }

    pub fn add_dispatcher<F>(mut self, dispatcher: Arc<ChannelDispatcher<T>>, handler: F) -> Self
    where
        F: Fn(T) + Send + Sync + 'static,
    {
        self.dispatchers.push(dispatcher);
        self.handlers.push(Box::new(handler));
        self
    }

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

    pub fn run(self) {
        let tagged_receivers = Arc::new(self.build_tagged_receivers());
        let handlers = Arc::new(self.handlers);
        let worker_cores = self.worker_cores.expect("Cores must be set via set_cores()");

        for core in worker_cores {
            let tagged_receivers_ref = Arc::clone(&tagged_receivers);
            let handlers_ref = Arc::clone(&handlers);

            thread::spawn(move || {
                if let Err(e) = pin_thread_to_core(core) {
                    eprintln!("Failed to pin thread to core {}: {}", core, e);
                }

                Self::run_worker_loop(tagged_receivers_ref, handlers_ref, core);
            });
        }
    }

    fn run_worker_loop(
        tagged_receivers: Vec<(usize, Arc<Receiver<T>>)>,
        handlers: Arc<Vec<Box<dyn Fn(T) + Send + Sync>>>,
        core: usize,
    ) {
        let mut select = Select::new();
        for (_, receiver) in &tagged_receivers {
            select.recv(receiver);
        }

        loop {
            let oper = select.select();
            let oper_index = oper.index();
            let (handler_index, receiver) = &tagged_receivers[oper_index];
            let handler = &handlers[*handler_index];

            match oper.recv(receiver) {
                Ok(data) => handler(data),
                Err(_) => {
                    eprintln!("Receiver {} disconnected on core {}, exiting", handler_index, core);
                    break;
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
