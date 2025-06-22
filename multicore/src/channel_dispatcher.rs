use retina_core::CoreId;
use crossbeam::channel::{bounded, Receiver, Sender, TrySendError};
use std::collections::HashMap;
use std::sync::Arc;
use thiserror::Error; 

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

    // Dispatch data to appropriate channel based on mode and core_id 
    pub fn dispatch(&self, data: T, core_id: Option<&CoreId>) -> Result<(), DispatchError<T>> {
        match &self.channels {
            Channels::PerCore(map) => {
                let core = core_id.ok_or(DispatchError::CoreIdRequired)?;
                let (sender, _) = map.get(core).ok_or(DispatchError::CoreNotFound(*core))?;
                sender.try_send(data).map_err(DispatchError::SendFailed)?;
            }
            Channels::Shared(sender, _) => {
                sender.try_send(data).map_err(DispatchError::SendFailed)?;
            }
        }
        Ok(())
    }


    pub fn receivers(&self) -> Vec<Arc<Receiver<T>>> {
        match &self.channels {
            Channels::PerCore(map) => map.values().map(|(_, rx)| Arc::clone(rx)).collect(),
            Channels::Shared(_, rx) => vec![Arc::clone(rx)],
        }
    }
}

#[derive(Debug, Error)]
pub enum DispatchError<T> {
    #[error("Core ID required for PerCore dispatch")]
    CoreIdRequired,

    #[error("No sender found for core: {0}")]
    CoreNotFound(CoreId),

    #[error("Failed to send data")]
    SendFailed(#[from] TrySendError<T>),
}
