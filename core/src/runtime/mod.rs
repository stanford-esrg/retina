//! Retina runtime.
//!
//! The runtime initializes the DPDK environment abstraction layer, creates memory pools, launches
//! the packet processing cores, and manages logging and display output.

mod offline;
mod online;
use self::offline::*;
use self::online::*;

use crate::config::*;
use crate::dpdk;
use crate::filter::{Filter, FilterFactory};
use crate::lcore::SocketId;
use crate::memory::mempool::Mempool;
use crate::subscription::*;

use std::collections::BTreeMap;
use std::ffi::CString;
use std::sync::Arc;

use anyhow::{bail, Result};

/// The Retina runtime.
///
/// The runtime initializes the DPDK environment abstraction layer, creates memory pools, launches
/// the packet processing cores, and manages logging and display output.
pub struct Runtime<'a, S>
where
    S: Subscribable,
{
    #[allow(dead_code)]
    mempools: BTreeMap<SocketId, Mempool>,
    online: Option<OnlineRuntime<'a, S>>,
    offline: Option<OfflineRuntime<'a, S>>,
    #[cfg(feature = "timing")]
    subscription: Arc<Subscription<'a, S>>,
}

impl<'a, S> Runtime<'a, S>
where
    S: Subscribable,
{
    /// Creates a new runtime from the `config` settings, filter, and callback.
    ///
    /// # Remarks
    ///
    /// The `factory` parameter is a macro-generated function pointer based on the user-defined
    /// filter string, and must take the value "`filter`". `cb` is the name of the user-defined
    /// callback function.
    ///
    /// # Example
    ///
    /// ```
    /// let mut runtime = Runtime::new(config, filter, callback)?;
    /// ```
    pub fn new(
        config: RuntimeConfig,
        factory: fn() -> FilterFactory,
        cb: impl Fn(S) + 'a,
    ) -> Result<Self> {
        let factory = factory();
        let filter =
            Filter::from_str(factory.filter_str.as_str(), true).expect("Failed to parse filter");
        let subscription = Arc::new(Subscription::new(factory, cb));

        println!("Initializing Retina runtime...");
        log::info!("Initializing EAL...");
        dpdk::load_drivers();
        {
            let eal_params = config.get_eal_params();
            let eal_params_len = eal_params.len() as i32;

            let mut args = vec![];
            let mut ptrs = vec![];
            for arg in eal_params.into_iter() {
                let s = CString::new(arg).unwrap();
                ptrs.push(s.as_ptr() as *mut u8);
                args.push(s);
            }

            let ret = unsafe { dpdk::rte_eal_init(eal_params_len, ptrs.as_ptr() as *mut _) };
            if ret < 0 {
                bail!("Failure initializing EAL");
            }
        }

        log::info!("Initializing Mempools...");
        let mut mempools = BTreeMap::new();
        let socket_ids = config.get_all_socket_ids();
        let mtu = if let Some(online) = &config.online {
            online.mtu
        } else if let Some(offline) = &config.offline {
            offline.mtu
        } else {
            Mempool::default_mtu()
        };
        for socket_id in socket_ids {
            log::debug!("Socket ID: {}", socket_id);
            let mempool = Mempool::new(&config.mempool, socket_id, mtu)?;
            mempools.insert(socket_id, mempool);
        }

        let online = config.online.as_ref().map(|cfg| {
            log::info!("Initializing Online Runtime...");
            let online_opts = OnlineOptions {
                online: cfg.clone(),
                conntrack: config.conntrack.clone(),
            };
            OnlineRuntime::new(
                &config,
                online_opts,
                &mut mempools,
                filter.clone(),
                Arc::clone(&subscription),
            )
        });

        let offline = config.offline.as_ref().map(|cfg| {
            log::info!("Initializing Offline Analysis...");
            let offline_opts = OfflineOptions {
                offline: cfg.clone(),
                conntrack: config.conntrack.clone(),
            };
            OfflineRuntime::new(
                offline_opts,
                &mempools,
                filter.clone(),
                Arc::clone(&subscription),
            )
        });

        log::info!("Runtime ready.");
        Ok(Runtime {
            mempools,
            online,
            offline,
            #[cfg(feature = "timing")]
            subscription,
        })
    }

    /// Run Retina for the duration specified in the configuration or until `ctrl-c` to terminate.
    ///
    /// # Example
    ///
    /// ```
    /// runtime.run();
    /// ```
    pub fn run(&mut self) {
        if let Some(online) = &mut self.online {
            online.run();
        } else if let Some(offline) = &self.offline {
            offline.run();
        } else {
            log::error!("No runtime");
        }
        #[cfg(feature = "timing")]
        {
            self.subscription.timers.display_stats();
            self.subscription.timers.dump_stats();
        }
        log::info!("Done.");
    }
}
