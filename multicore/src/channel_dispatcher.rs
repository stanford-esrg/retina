use retina_core::CoreId;
use crossbeam::channel::{bounded, Receiver, Sender};
use std::collections::HashMap;
use std::sync::Arc;

#[derive(Clone)]
pub enum ChannelMode {
    Shared,
    PerCore(Vec<CoreId>),
}

pub enum Channels<T> {
    Shared(Sender<T>, Arc<Receiver<T>>),
    PerCore(HashMap<CoreId, (Sender<T>, Arc<Receiver<T>>)>),
}

pub struct ChannelDispatcher<T> {
    channels: Channels<T>,
}

impl<T: Send + 'static> ChannelDispatcher<T> {
    pub fn new(mode: ChannelMode, channel_size: usize) -> Self {
        match mode {
            ChannelMode::Shared => Self::new_shared(channel_size),
            ChannelMode::PerCore(rx_cores) => Self::new_percore(&rx_cores, channel_size),
        }
    }

    fn new_shared(channel_size: usize) -> Self {
        let (tx, rx) = bounded(channel_size);
        Self {
            channels: Channels::Shared(tx, Arc::new(rx)),
        }
    }

    fn new_percore(rx_cores: &[CoreId], channel_size: usize) -> Self {
        let mut map = HashMap::with_capacity(rx_cores.len());
        for &core in rx_cores {
            let (tx, rx) = bounded(channel_size);
            map.insert(core, (tx, Arc::new(rx)));
        }
        Self {
            channels: Channels::PerCore(map),
        }
    }

    pub fn dispatch(&self, data: T, core_id: Option<&CoreId>) {
        match &self.channels {
            Channels::PerCore(map) => {
                if let Some(core) = core_id {
                    if let Some((sender, _)) = map.get(core) {
                        if let Err(e) = sender.try_send(data) {
                            eprintln!("Failed to send data to core {}: {:?}", core, e);
                        }
                    } else {
                        eprintln!("No sender found for core: {}", core);
                    }
                } else {
                    eprintln!("Core ID required for PerCore dispatch but not provided.");
                }
            }
            Channels::Shared(sender, _) => {
                if let Err(e) = sender.try_send(data) {
                    eprintln!("Failed to send data on shared channel: {:?}", e);
                }
            }
        }
    }

    pub fn receivers(&self) -> Vec<Arc<Receiver<T>>> {
        match &self.channels {
            Channels::PerCore(map) => map.values().map(|(_, rx)| Arc::clone(rx)).collect(),
            Channels::Shared(_, rx) => vec![Arc::clone(rx)],
        }
    }
}
