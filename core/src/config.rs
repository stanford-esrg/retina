//! Configuration options.
//!
//! While applications that use Retina are free to define their own command line arguments, Retina
//! requires a separate configuration file that defines runtime options for CPU and memory usage,
//! network interface(s), logging, protocol-specific items, and more. The path to the configuration
//! file itself will typically be a command line argument passed to the application.
//!
//!  Retina can run in either "online" mode (reading packets from a live network interface) or
//! "offline" mode (reading packets from a capture file). See
//! [configs](https://github.com/stanford-esrg/retina/tree/main/configs) for examples.

use crate::lcore::{CoreId, SocketId};

use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};

/// Loads a configuration file from `path`.
pub fn load_config<P: AsRef<Path>>(path: P) -> RuntimeConfig {
    let config_str = fs::read_to_string(path).expect("ERROR: File read failed");
    let config: RuntimeConfig = toml::from_str(&config_str).expect("Invalid config file");

    // error check config
    if config.online.is_some() == config.offline.is_some() {
        log::error!(
            "Configure either live ports or offline analysis: {:#?}",
            config
        );
        panic!();
    }
    config
}

/// Loads a default configuration file.
///
/// For demonstration purposes only, not configured for performance. The default configuration
/// assumes Retina is being run from the crate root in offline mode:
/// ```toml
/// main_core = 0
///
/// [mempool]
///     capacity = 8192
///
/// [offline]
///     pcap = "./traces/small_flows.pcap"
///     mtu = 9702
///
/// [conntrack]
///     max_connections = 100_000
/// ```
pub fn default_config() -> RuntimeConfig {
    RuntimeConfig::default()
}

/* --------------------------------------------------------------------------------- */

/// Runtime configuration options.
#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct RuntimeConfig {
    /// Main core identifier. Initializes and manages packet processing cores and logging, but does
    /// not process packets itself.
    pub main_core: u32,

    /// Sets the number of memory channels to use.
    ///
    /// This controls the spread layout used by the memory allocator and is mainly for performance
    /// optimization. Can be configured up to be the number of channels per CPU socket if the
    /// platform supports multiple memory channels. Defaults to `1`.
    #[serde(default = "default_nb_memory_channels")]
    pub nb_memory_channels: usize,

    /// Suppress DPDK runtime logging and telemetry output. Defaults to `true`.
    #[serde(default = "default_suppress_dpdk_output")]
    pub suppress_dpdk_output: bool,

    /// Per-mempool settings.
    pub mempool: MempoolConfig,

    /// Online mode settings. Either `online` or `offline` must be specified.
    #[serde(default = "default_online")]
    pub online: Option<OnlineConfig>,

    /// Offline mode settings. Either `online` or `offline` must be specified.
    #[serde(default = "default_offline")]
    pub offline: Option<OfflineConfig>,

    /// Connection tracking settings.
    pub conntrack: ConnTrackConfig,

    #[doc(hidden)]
    /// Runtime filter for testing purposes.
    #[serde(default = "default_filter")]
    pub filter: Option<String>,
}

impl RuntimeConfig {
    /// Returns a list of core IDs assigned to the runtime.
    fn get_all_core_ids(&self) -> Vec<CoreId> {
        let mut cores = vec![CoreId(self.main_core)];
        if let Some(online) = &self.online {
            for port in online.ports.iter() {
                cores.extend(port.cores.iter().map(|c| CoreId(*c)));
                if let Some(sink) = &port.sink {
                    cores.push(CoreId(sink.core));
                }
            }
        }
        cores.sort();
        cores.dedup();
        cores
    }

    /// Returns a list of socket IDs in use.
    pub(crate) fn get_all_socket_ids(&self) -> Vec<SocketId> {
        let mut sockets = vec![];
        for core_id in self.get_all_core_ids() {
            sockets.push(core_id.socket_id());
        }
        sockets.sort();
        sockets.dedup();
        sockets
    }

    /// Returns DPDK EAL parameters.
    #[allow(clippy::vec_init_then_push)]
    pub(crate) fn get_eal_params(&self) -> Vec<String> {
        let mut eal_params = vec![];

        eal_params.push("--main-lcore".to_owned());
        eal_params.push(self.main_core.to_string());

        eal_params.push("-l".to_owned());
        let core_list: Vec<String> = self
            .get_all_core_ids()
            .iter()
            .map(|c| c.raw().to_string())
            .collect();
        eal_params.push(core_list.join(","));

        if let Some(online) = &self.online {
            for supl_arg in online.dpdk_supl_args.iter() {
                eal_params.push(supl_arg.to_string())
            }
            for port in online.ports.iter() {
                eal_params.push("-a".to_owned());
                eal_params.push(port.device.to_string());
            }
        }

        eal_params.push("-n".to_owned());
        eal_params.push(self.nb_memory_channels.to_string());

        if self.suppress_dpdk_output {
            eal_params.push("--log-level=6".to_owned());
            eal_params.push("--no-telemetry".to_owned());
        }

        eal_params
    }
}

fn default_nb_memory_channels() -> usize {
    1
}

fn default_suppress_dpdk_output() -> bool {
    true
}

fn default_online() -> Option<OnlineConfig> {
    None
}

fn default_offline() -> Option<OfflineConfig> {
    None
}

fn default_filter() -> Option<String> {
    None
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        RuntimeConfig {
            main_core: 0,
            nb_memory_channels: 1,
            suppress_dpdk_output: true,
            mempool: MempoolConfig {
                capacity: 8192,
                cache_size: 512,
            },
            online: None,
            offline: Some(OfflineConfig {
                mtu: 9702,
                // assumes Retina is being run from crate root
                pcap: "./traces/small_flows.pcap".to_string(),
            }),
            conntrack: ConnTrackConfig {
                max_connections: 100_000,
                max_out_of_order: 100,
                timeout_resolution: 100,
                udp_inactivity_timeout: 60_000,
                tcp_inactivity_timeout: 300_000,
                tcp_establish_timeout: 5000,
                init_synack: false,
                init_fin: false,
                init_rst: false,
                init_data: false,
            },
            filter: None,
        }
    }
}

/* --------------------------------------------------------------------------------- */

/// Memory pool options.
///
/// Retina manages packet buffer memory using DPDK's pool-based memory allocator. This takes
/// advantage of built-in DPDK huge page support, NUMA affinity, and access to DMA addresses. See
/// [Memory in DPDK](https://www.dpdk.org/blog/2019/08/21/memory-in-dpdk-part-1-general-concepts/)
/// for more details.
///
/// ## Example
/// ```toml
/// [mempool]
///     capacity = 1_048_576
///     cache_size = 512
/// ```
#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct MempoolConfig {
    /// Number of mbufs allocated per mempool. The maximum value that can be set will depend on
    /// the available memory (number of hugepages allocated) and the MTU. Defaults to `65536`.
    #[serde(default = "default_capacity")]
    pub capacity: usize,

    /// The size of the per-core object cache. It is recommended that `cache_size` evenly divides
    /// `capacity`. Defaults to `512`.
    #[serde(default = "default_cache_size")]
    pub cache_size: usize,
}

fn default_capacity() -> usize {
    65536
}

fn default_cache_size() -> usize {
    512
}

/* --------------------------------------------------------------------------------- */

/// Live traffic analysis options.
///
/// Online mode performs traffic analysis on a live network interface. Either
/// [OnlineConfig](OnlineConfig) or [OfflineConfig](OfflineConfig) must be specified, but not both.
///
/// ## Example
/// ```toml
/// [online]
///     duration = 30
///     nb_rxd = 32768
///     promiscuous = true
///     mtu = 1500
///     hardware_assist = true
///     dpdk_supl_args = []
///
/// [online.monitor.display]
///     throughput = true
///     mempool_usage = true
///
///     [online.monitor.log]
///         directory = "./log"
///         interval = 1000
///
///     [[online.ports]]
///         device = "0000:3b:00.0"
///         cores = [1,2,3,4]
///
///     [[online.ports]]
///         device = "0000:3b:00.1"
///         cores = [5,6,7,8]
/// ```
#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct OnlineConfig {
    /// If set, the applicaton will stop after `duration` seconds. Defaults to `None`.
    #[serde(default = "default_duration")]
    pub duration: Option<u64>,

    /// Whether promiscuous mode is enabled for all ports. Defaults to `true`.
    #[serde(default = "default_promiscuous")]
    pub promiscuous: bool,

    /// The number of RX descriptors per receive queue. Defaults to `4096`.
    ///
    /// Receive queues are polled for packets using a run-to-completion model. Deeper queues will be
    /// more tolerant of processing delays at the cost of higher memory usage and hugepage
    /// reservation.
    #[serde(default = "default_portqueue_nb_rxd")]
    pub nb_rxd: usize,

    /// Maximum transmission unit (in bytes) allowed for ingress packets. Defaults to `1500`.
    ///
    /// To capture jumbo frames, set this value higher (e.g., `9702`).
    #[serde(default = "default_mtu")]
    pub mtu: usize,

    /// If set, will attempt to offload parts of the filter to the NIC, depending on its hardware
    /// filtering support. Defaults to `true`.
    #[serde(default = "default_hardware_assist")]
    pub hardware_assist: bool,

    /// If set, will pass supplementary arguments to DPDK EAL (see DPDK
    /// configuration). For instance `--no-huge`.
    /// Defaults to empty string.
    #[serde(default = "default_dpdk_supl_args")]
    pub dpdk_supl_args: Vec<String>,

    /// Live performance monitoring. Defaults to `None`.
    #[serde(default = "default_monitor")]
    pub monitor: Option<MonitorConfig>,

    /// List of network interfaces to read from.
    pub ports: Vec<PortMap>,
}

fn default_duration() -> Option<u64> {
    None
}

fn default_hardware_assist() -> bool {
    true
}

fn default_dpdk_supl_args() -> Vec<String> {
    Vec::new()
}

fn default_promiscuous() -> bool {
    true
}

fn default_portqueue_nb_rxd() -> usize {
    4096
}

fn default_mtu() -> usize {
    1500
}

fn default_monitor() -> Option<MonitorConfig> {
    None
}

/* --------------------------------------------------------------------------------- */

/// Sink core options.
///
/// A "sink" core is a utility core whose sole purpose is to drop received traffic. This is useful
/// for connection sampling, as entire 4-tuples can be discarded by redirecting them to the sink
/// core.
///
/// ## Remarks
/// Adding a sink core prevents ethtool counters from classifying intentionally discarded packets as
/// packet loss. However, it can be quite wasteful of system resources, as it requires configuring
/// one additional core per interface and thrashes the cache.
///
/// ## Example
/// ```toml
/// [online.ports.sink]
///     core = 9
///     nb_buckets = 384   # drops 25% of 4-tuples
/// ```
#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct SinkConfig {
    /// Sink core identifier.
    pub core: u32,

    /// Number of RSS redirection table buckets to use for receive queues. Defaults to `512`, which
    /// indicates no sampling.
    ///
    /// ## Remarks
    /// Connection sampling is implemented by only polling from a fraction of the available RSS
    /// redirection buckets. `nb_buckets` must range from the number of cores polling the port (call
    /// this `n`) to `512`, which is the maximum number of buckets in the RSS redirection table. It
    /// is recommended that `nb_buckets` be a multiple of `n` for better load balancing. For
    /// example, setting `nb_buckets = 256` would drop 50% of connections.
    #[serde(default = "default_nb_buckets")]
    pub nb_buckets: usize,
}

fn default_nb_buckets() -> usize {
    512
}

/* --------------------------------------------------------------------------------- */

/// Network interface options.
///
/// ## Example
/// ```toml
/// [[online.ports]]
///     device = "0000:3b:00.0"
///     cores = [1,2,3,4,5,6,7,8]
/// ```
#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct PortMap {
    /// PCI address of interface.
    pub device: String,

    /// List of packet processing cores used to poll the interface.
    ///
    /// ## Remarks
    /// For performance, it is recommended that the processing cores reside on the same NUMA node as
    /// the PCI device.
    pub cores: Vec<u32>,

    /// Sink core configuration. Defaults to `None`.
    #[serde(default = "default_sink")]
    pub sink: Option<SinkConfig>,
}

fn default_sink() -> Option<SinkConfig> {
    None
}

/* --------------------------------------------------------------------------------- */

/// Statistics logging and live monitoring operations.
///
/// ## Example
/// ```toml
/// [online.monitor.display]
///     throughput = true
///     mempool_usage = true
///
/// [online.monitor.log]
///     directory = "./log"
///     interval = 1000
/// ```
#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct MonitorConfig {
    /// Live display configuration. Defaults to `None` (no output).
    #[serde(default = "default_display")]
    pub display: Option<DisplayConfig>,

    /// Logging configuration. Defaults to `None` (no logs).
    #[serde(default = "default_log")]
    pub log: Option<LogConfig>,
}

fn default_display() -> Option<DisplayConfig> {
    None
}

fn default_log() -> Option<LogConfig> {
    None
}

/* --------------------------------------------------------------------------------- */

/// Live statistics display options.
///
/// If enabled, live statistics will be displayed to stdout once per second.
///
/// ## Example
/// ```toml
/// [online.monitor.display]
///     throughput = true
///     mempool_usage = true
/// ```
#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct DisplayConfig {
    /// Display live throughputs. Defaults to `true`.
    #[serde(default = "default_display_throughput")]
    pub throughput: bool,

    /// Display live mempool usage. Defaults to `true`.
    #[serde(default = "default_display_mempool_usage")]
    pub mempool_usage: bool,

    /// List of live port statistics to display.
    ///
    /// ## Remarks
    /// Available options vary depending on the NIC driver and its supported counters. A port
    /// statistic will be displayed if it contains (as a substring) any item in the `port_stats`
    /// list. To display all available port statistics, set this value to a list containing the
    /// empty string (`port_stats = [""]`). Defaults to displaying no statistics (`port_stats =
    /// []`).
    #[serde(default = "default_display_port_stats")]
    pub port_stats: Vec<String>,
}

fn default_display_throughput() -> bool {
    true
}

fn default_display_mempool_usage() -> bool {
    true
}

fn default_display_port_stats() -> Vec<String> {
    vec![]
}

/* --------------------------------------------------------------------------------- */

/// Logging options.
///
/// ## Example
/// ```toml
/// [online.monitor.log]
///     directory = "./log"
///     interval = 1000
///     port_stats = ["rx"]   # only log stats with "rx" in its name
/// ```
#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct LogConfig {
    /// Log directory path. If logging is enabled, Retina will write logs to a timestamped folder
    /// inside `directory`. Defaults to `"./log"`.
    #[serde(default = "default_log_directory")]
    pub directory: String,

    /// How often to log port statistics (in milliseconds). Defaults to `1000`.
    #[serde(default = "default_log_interval")]
    pub interval: u64,

    /// List of port statistics to log.
    ///
    /// Available options vary depending on the NIC driver and its supported counters. A port
    /// statistic will be logged if it contains (as a substring) any item in the `port_stats` list.
    /// To log all available port statistics, set this value to a list containing the empty string
    /// (`port_stats = [""]`). Defaults to logging receive statistics (`port_stats = ["rx"]`).
    #[serde(default = "default_log_port_stats")]
    pub port_stats: Vec<String>,
}

fn default_log_directory() -> String {
    "./log/".to_string()
}

fn default_log_interval() -> u64 {
    1000
}

fn default_log_port_stats() -> Vec<String> {
    vec!["rx".to_string()]
}

/* --------------------------------------------------------------------------------- */

/// Offline traffic analysis options.
///
/// Offline mode runs using a single core and performs offline analysis of already captured pcap
/// files. Either [OnlineConfig](OnlineConfig) or [OfflineConfig](OfflineConfig) must be specified,
/// but not both. This mode is primarily intended for functional testing.
///
/// ## Example
/// ```toml
/// [offline]
///     pcap = "sample_pcaps/smallFlows.pcap"
///     mtu = 9702
/// ```
#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct OfflineConfig {
    /// Path to packet capture (pcap) file.
    pub pcap: String,

    /// Maximum frame size, equivalent to MTU on a live interface. Defaults to `1500`.
    ///
    /// To include jumbo frames, set this value higher (e.g., `9702`).
    #[serde(default = "default_mtu")]
    pub mtu: usize,
}

/* --------------------------------------------------------------------------------- */

/// Connection tracking options.
///
/// These options can be used to tune for resource usage vs. accuracy depending on expected network
/// characteristics.
///
/// ## Example
/// ```toml
/// [conntrack]
///     max_connections = 10_000_000
///     max_out_of_order = 100
///     timeout_resolution = 100
///     udp_inactivity_timeout = 60_000
///     tcp_inactivity_timeout = 300_000
///     tcp_establish_timeout = 5000
/// ```
#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct ConnTrackConfig {
    /// Maximum number of connections that can be tracked simultaneously per-core. Defaults to
    /// `10_000_000`.
    #[serde(default = "default_max_connections")]
    pub max_connections: usize,

    /// Maximum number of out-of-order packets allowed per TCP connection before it is force
    /// expired. Defaults to `100`.
    #[serde(default = "default_max_out_of_order")]
    pub max_out_of_order: usize,

    /// Frequency to check for inactive streams (in milliseconds). Defaults to `1000` (1 second).
    #[serde(default = "default_timeout_resolution")]
    pub timeout_resolution: usize,

    /// A UDP connection can be inactive for up to this amount of time (in milliseconds) before it
    /// is force expired. Defaults to `60_000` (1 minute).
    #[serde(default = "default_udp_inactivity_timeout")]
    pub udp_inactivity_timeout: usize,

    /// A TCP connection can be inactive for up to this amount of time (in milliseconds) before it
    /// is force expired. Defaults to `300_000` (5 minutes).
    #[serde(default = "default_tcp_inactivity_timeout")]
    pub tcp_inactivity_timeout: usize,

    /// Inactivity time between the first and second packet of a TCP connection before it is force
    /// expired (in milliseconds).
    ///
    /// This approximates connections that remain inactive in either the `SYN-SENT` or
    /// `SYN-RECEIVED` state without progressing. It is used to prevent memory exhaustion due to SYN
    /// scans and SYN floods. Defaults to `5000` (5 seconds).
    #[serde(default = "default_tcp_establish_timeout")]
    pub tcp_establish_timeout: usize,

    #[doc(hidden)]
    /// Whether to track TCP connections where the first observed packet is a SYN/ACK. Defaults to
    /// `false`.
    #[serde(default = "default_init_synack")]
    pub init_synack: bool,

    #[doc(hidden)]
    /// Whether to track TCP connections where the first observed packet is a FIN. Defaults to
    /// `false`.
    #[serde(default = "default_init_fin")]
    pub init_fin: bool,

    #[doc(hidden)]
    /// Whether to track TCP connections where the first observed packet is a RST. Defaults to
    /// `false`.
    #[serde(default = "default_init_rst")]
    pub init_rst: bool,

    #[doc(hidden)]
    /// Whether to track TCP connections where the first observed packet is a DATA. Defaults to
    /// `false`.
    #[serde(default = "default_init_data")]
    pub init_data: bool,
}

fn default_max_connections() -> usize {
    10_000_000
}

fn default_max_out_of_order() -> usize {
    100
}

fn default_timeout_resolution() -> usize {
    1000
}

fn default_udp_inactivity_timeout() -> usize {
    60_000
}

fn default_tcp_inactivity_timeout() -> usize {
    300_000
}

fn default_tcp_establish_timeout() -> usize {
    5000
}

fn default_init_synack() -> bool {
    false
}

fn default_init_fin() -> bool {
    false
}

fn default_init_rst() -> bool {
    false
}

fn default_init_data() -> bool {
    false
}
