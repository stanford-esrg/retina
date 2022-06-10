use crate::config::{ConnTrackConfig, OnlineConfig, RuntimeConfig};
use crate::dpdk;
use crate::filter::Filter;
use crate::lcore::monitor::Monitor;
use crate::lcore::rx_core::RxCore;
use crate::lcore::{CoreId, SocketId};
use crate::memory::mempool::Mempool;
use crate::port::*;
use crate::subscription::*;

use std::collections::BTreeMap;
use std::os::raw::{c_uint, c_void};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Instant;

pub(crate) struct OnlineRuntime<'a, S>
where
    S: Subscribable,
{
    ports: BTreeMap<PortId, Port>,
    rx_cores: BTreeMap<CoreId, RxCore<'a, S>>,
    monitor: Monitor,
    filter: Filter,
    options: OnlineOptions,
}

impl<'a, S> OnlineRuntime<'a, S>
where
    S: Subscribable,
{
    pub(crate) fn new(
        config: &RuntimeConfig,
        options: OnlineOptions,
        mempools: &mut BTreeMap<SocketId, Mempool>,
        filter: Filter,
        subscription: Arc<Subscription<'a, S>>,
    ) -> Self {
        // Set up signal handler
        let is_running = Arc::new(AtomicBool::new(true));
        let r = Arc::clone(&is_running);
        ctrlc::set_handler(move || {
            r.store(false, Ordering::Relaxed);
        })
        .expect("Error setting Ctrl-C handler");

        log::info!("Initializing Ports...");
        let mut ports: BTreeMap<PortId, Port> = BTreeMap::new();
        for port_map in options.online.ports.iter() {
            let port = Port::new(port_map);
            let socket_id = port.id.socket_id();
            mempools.entry(socket_id).or_insert_with(|| {
                // Create a local mempool if user is not polling the port
                // from the same socket.
                let mtu = if let Some(online) = &config.online {
                    online.mtu
                } else {
                    Mempool::default_mtu()
                };
                Mempool::new(&config.mempool, socket_id, mtu)
                    .expect("Unable to initialize local mempool")
            });
            port.init(
                mempools,
                options.online.nb_rxd,
                options.online.mtu,
                options.online.promiscuous,
            )
            .expect("Failed to initialize port.");
            ports.insert(port.id, port);
        }

        log::info!("Initializing RX Cores...");
        let mut rx_cores: BTreeMap<CoreId, RxCore<S>> = BTreeMap::new();
        let mut core_map: BTreeMap<CoreId, Vec<RxQueue>> = BTreeMap::new();
        for (_port_id, port) in ports.iter() {
            for (rxqueue, core_id) in port.queue_map.iter() {
                core_map
                    .entry(*core_id)
                    .or_insert_with(Vec::new)
                    .push(*rxqueue);
            }
        }
        for (core_id, rxqueues) in core_map.into_iter() {
            let rx_core = RxCore::new(
                core_id,
                rxqueues,
                filter.clone(),
                options.conntrack.clone(),
                Arc::clone(&subscription),
                Arc::clone(&is_running),
            );
            rx_cores.insert(core_id, rx_core);
        }

        let monitor = Monitor::new(config, &ports, Arc::clone(&is_running));

        OnlineRuntime {
            ports,
            rx_cores,
            monitor,
            filter,
            options,
        }
    }

    pub(crate) fn run(&mut self) {
        self.start_ports();

        log::info!("Launching RX cores...");
        for (core_id, _rx_core) in self.rx_cores.iter() {
            let role = unsafe { dpdk::rte_eal_lcore_role(core_id.raw()) };
            if role != dpdk::rte_lcore_role_t_ROLE_RTE {
                log::error!("Attempted to launch non-DPDK core");
                panic!();
            }

            let arg = &self.rx_cores as *const _ as *mut c_void;
            let ret = unsafe {
                dpdk::rte_eal_remote_launch(Some(launch_rx::<S>), arg, core_id.raw() as c_uint)
            };
            if ret != 0 {
                log::error!("RX Core {} busy, launch failed.", core_id);
                panic!();
            }
        }

        // run main thread
        self.run_main();
        unsafe { dpdk::rte_eal_mp_wait_lcore() };

        log::info!("Exiting loop...");
        self.stop_ports();
    }

    fn run_main(&mut self) {
        let id = unsafe { dpdk::rte_lcore_id() };
        log::info!("Running main on Core {}", id);
        let start = Instant::now();
        self.monitor.run();
        println!("Main done. Ran for {:?}", start.elapsed());
    }

    fn start_ports(&self) {
        log::info!("Starting ports...");
        for port in self.ports.values() {
            port.start();

            if self.options.online.hardware_assist {
                log::info!("Applying hardware filters...");
                let res = self.filter.set_hardware_filter(port);
                match res {
                    Ok(_) => (),
                    Err(error) => {
                        log::warn!("Failed to apply some patterns, passing all traffic through Port {}. Reason: {}", port.id, error);
                    }
                }
            } else {
                log::info!("No hardware assist configured for port {}, passing all traffic through device.", port.id);
            }
        }
    }

    fn stop_ports(&self) {
        log::info!("Stopping ports...");
        for port in self.ports.values() {
            port.stop();
        }
    }
}

/// Read-only runtime options for the offline core
#[derive(Debug)]
pub(crate) struct OnlineOptions {
    pub(crate) online: OnlineConfig,
    pub(crate) conntrack: ConnTrackConfig,
}

extern "C" fn launch_rx<S>(arg: *mut c_void) -> i32
where
    S: Subscribable,
{
    // enforce that workers cores cannot mutate runtime
    // TODO: make this *const and use Mutex for interior mutability
    let rx_cores = arg as *const BTreeMap<CoreId, RxCore<S>>;
    let rx_cores = unsafe { &*rx_cores };

    let core_id = CoreId(unsafe { dpdk::rte_lcore_id() } as u32);
    let rx_core = rx_cores.get(&core_id).expect("Invalid Core");

    // TODO: slight optimization: even if filter is nonempty, if the hardware takes care of the
    // whole thing we can also run_rx with no filter
    rx_core.rx_loop();
    0
}
