use std::sync::Arc;
use std::thread;
use crossbeam::channel::Select;
use crate::{ChannelDispatcher, pin_thread_to_core};

pub struct DedicatedWorkerThreadSpawner<T, F> 
where
    F: Fn(T) + Send + Sync + Clone + 'static,
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
        let worker_cores = self.worker_cores.expect("Cores not set");
        let dispatcher = self.dispatcher.expect("Dispatcher not set");
        let thread_fn = self.thread_fn.expect("Thread function not set");

        let receivers = dispatcher.receivers();

        for core in worker_cores {
            let receivers_clone = receivers.clone();
            let thread_fn = thread_fn.clone();

            thread::spawn(move || {
                if let Err(e) = pin_thread_to_core(core) {
                    eprintln!("Failed to pin thread to core {}: {}", core, e);
                }

                if receivers_clone.len() == 1 {
                    let receiver = &receivers_clone[0];
                    while let Ok(data) = receiver.recv() {
                        thread_fn(data);
                    }
                } else {
                    let mut select = Select::new();
                    for receiver in &receivers_clone {
                        select.recv(receiver);
                    }

                    loop {
                        let oper = select.select();
                        let index = oper.index();

                        match oper.recv(&receivers_clone[index]) {
                            Ok(data) => thread_fn(data),
                            Err(_) => break,
                        }
                    }
                }
            });
        }
    }
}
