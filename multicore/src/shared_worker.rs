use std::sync::Arc;
use std::thread;
use crossbeam::channel::Select;
use crate::{ChannelDispatcher, pin_thread_to_core};

pub struct SharedWorkerThreadSpawner<T>
where
    T: Send + Clone + 'static,
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

    pub fn run(self) {
        let worker_cores = self.worker_cores.expect("Cores not set");
        let handlers = Arc::new(self.handlers); 

        let mut tagged_receivers = Vec::new();
        for (index, dispatcher) in self.dispatchers.iter().enumerate() {
            let receivers = dispatcher.receivers();
            for receiver in receivers {
                tagged_receivers.push((index, receiver));
            }
        }

        for core in worker_cores {
            let tagged_receivers_clone = tagged_receivers.clone();
            let handlers_clone = Arc::clone(&handlers);

            thread::spawn(move || {
                if let Err(e) = pin_thread_to_core(core) {
                    eprintln!("Failed to pin thread to core {}: {}", core, e);
                }

                let mut select = Select::new();
                for (_, receiver) in &tagged_receivers_clone {
                    select.recv(receiver);
                }

                loop {
                    let oper = select.select();
                    let oper_index = oper.index();
                    let (handler_index, receiver) = &tagged_receivers_clone[oper_index];
                    let handler = &handlers_clone[*handler_index];

                    match oper.recv(receiver) {
                        Ok(data) => handler(data),
                        Err(_) => {
                            eprintln!("Receiver {} disconnected on core {}, exiting thread.", handler_index, core);
                            break;
                        }
                    }
                }
            });
        }
    }
}
