//! Prometheus statistics.
//!
//! Retina uses the Prometheus time series database to record and report metrics useful for monitoring and
//! analysing retina usage over time. You can use Prometheus with other services like Grafana to use the
//! reported data.
//!
//! You can enable a exporter http server from `online.prometheus` config:
//! ```toml
//! [online.prometheus]
//!     port = 9898
//! ```
//! Then you
//! can [install Prometheus](https://prometheus.io/docs/prometheus/latest/installation/) and
//! use this config to scrape metrics from Retina:
//!
//! ```yaml
//! global:
//!     scrape_interval: 1s
//!     evaluation_interval: 1s
//! scrape_configs:
//!     - job_name: retina
//!       static_configs:
//!           - targets: ['127.0.0.1:9898']
//! ```
//!
//! After running prometheus, you can see simple graph of a prometheus query using its
//! web gui, for example:
//! ```txt
//! rate(retina_worker_received_pkts[10s])
//! ```
//! shows the number of received packets per second. For more complex usages, see
//! [Prometheus docs](https://prometheus.io/docs/introduction/overview/).
//!
//! You can also use the [`register_base_prometheus_registry`] function
//! to add your own metrics to the prometheus registry.

use http_body_util::Full;
use hyper::{
    body::{Body, Bytes},
    header::CONTENT_TYPE,
    Request, Response,
};
use prometheus_client::{
    encoding::EncodeLabelSet,
    metrics::{counter::Counter, family::Family},
    registry::{Registry, Unit},
};
use std::{
    fmt::Write,
    sync::{LazyLock, Mutex, OnceLock},
};

use super::*;
use crate::CoreId;

impl EncodeLabelSet for CoreId {
    fn encode(
        &self,
        mut encoder: prometheus_client::encoding::LabelSetEncoder,
    ) -> Result<(), std::fmt::Error> {
        let mut label = encoder.encode_label();
        let mut key = label.encode_label_key()?;
        key.write_str("core")?;
        let mut value = key.encode_label_value()?;
        write!(value, "{}", self.0)?;
        value.finish()
    }
}

#[derive(Default)]
struct Families {
    ignored_by_packet_filter_pkt: Family<CoreId, Counter>,
    ignored_by_packet_filter_byte: Family<CoreId, Counter>,
    dropped_middle_of_connection_tcp_pkt: Family<CoreId, Counter>,
    dropped_middle_of_connection_tcp_byte: Family<CoreId, Counter>,
    total_pkt: Family<CoreId, Counter>,
    total_byte: Family<CoreId, Counter>,
    tcp_pkt: Family<CoreId, Counter>,
    tcp_byte: Family<CoreId, Counter>,
    udp_pkt: Family<CoreId, Counter>,
    udp_byte: Family<CoreId, Counter>,
    tcp_new_connections: Family<CoreId, Counter>,
    udp_new_connections: Family<CoreId, Counter>,
    idle_cycles: Family<CoreId, Counter>,
    total_cycles: Family<CoreId, Counter>,
}

static FAMILIES: LazyLock<Families> = LazyLock::new(Families::default);

pub(crate) struct DpdkPrometheusStats {
    pub(crate) ingress_bits: Counter,
    pub(crate) ingress_pkts: Counter,
    pub(crate) good_bits: Counter,
    pub(crate) good_pkts: Counter,
    pub(crate) process_bits: Counter,
    pub(crate) process_pkts: Counter,
    pub(crate) hw_dropped_pkts: Counter,
    pub(crate) sw_dropped_pkts: Counter,
}

pub(crate) static BASE_STAT_REGISTRY: OnceLock<Mutex<Option<Registry>>> = OnceLock::new();

/// Retina uses prometheus to report metrics. You can use this function to
/// add your own metrics to the prometheus registry.
pub fn register_base_prometheus_registry(r: Registry) {
    if BASE_STAT_REGISTRY.set(Mutex::new(Some(r))).is_err() {
        panic!(
            "Base registry already set. You should call `register_base_prometheus_registry` only \
                once before building the runtime."
        );
    }
}

pub(crate) static STAT_REGISTRY: LazyLock<Registry> = LazyLock::new(|| {
    let mut r = BASE_STAT_REGISTRY
        .get_or_init(|| Mutex::new(Some(Registry::default())))
        .lock()
        .unwrap()
        .take()
        .unwrap();
    r.register_with_unit(
        "dpdk_ingress",
        "Number of bits received by the NIC.",
        Unit::Bytes,
        DPDK_STATS.ingress_bits.clone(),
    );
    r.register_with_unit(
        "dpdk_ingress",
        "Number of packets received by the NIC.",
        Unit::Other("pkts".to_string()),
        DPDK_STATS.ingress_pkts.clone(),
    );
    r.register_with_unit(
        "dpdk_good",
        "Number of bytes received by the DPDK.",
        Unit::Bytes,
        DPDK_STATS.good_bits.clone(),
    );
    r.register_with_unit(
        "dpdk_good",
        "Number of packets received by the DPDK.",
        Unit::Other("pkts".to_string()),
        DPDK_STATS.good_pkts.clone(),
    );
    r.register_with_unit(
        "dpdk_processed",
        "Number of bytes received by the DPDK.",
        Unit::Bytes,
        DPDK_STATS.process_bits.clone(),
    );
    r.register_with_unit(
        "dpdk_processed",
        "Number of packets received by the DPDK.",
        Unit::Other("pkts".to_string()),
        DPDK_STATS.process_pkts.clone(),
    );
    r.register_with_unit(
        "dpdk_hw_dropped",
        "Number of packets dropped by hardware.",
        Unit::Other("pkts".to_string()),
        DPDK_STATS.hw_dropped_pkts.clone(),
    );
    r.register_with_unit(
        "dpdk_sw_dropped",
        "Number of packets dropped by software.",
        Unit::Other("pkts".to_string()),
        DPDK_STATS.sw_dropped_pkts.clone(),
    );

    r.register_with_unit(
        "retina_ignored_by_packet_filter",
        "Number of packets ignored by packet filter.",
        Unit::Other("pkts".to_string()),
        FAMILIES.ignored_by_packet_filter_pkt.clone(),
    );
    r.register_with_unit(
        "retina_ignored_by_packet_filter",
        "Number of bytes ignored by packet filter.",
        Unit::Bytes,
        FAMILIES.ignored_by_packet_filter_byte.clone(),
    );
    r.register_with_unit(
        "retina_dropped_middle_of_connection_tcp",
        "Number of packets dropped due missing SYN packet.",
        Unit::Other("pkts".to_string()),
        FAMILIES.dropped_middle_of_connection_tcp_pkt.clone(),
    );
    r.register_with_unit(
        "retina_dropped_middle_of_connection_tcp",
        "Number of bytes dropped due missing SYN packet.",
        Unit::Bytes,
        FAMILIES.dropped_middle_of_connection_tcp_byte.clone(),
    );
    r.register_with_unit(
        "retina_worker_received",
        "Number of total packets received from dpdk.",
        Unit::Other("pkts".to_string()),
        FAMILIES.total_pkt.clone(),
    );
    r.register_with_unit(
        "retina_worker_received",
        "Number of total bytes received from dpdk.",
        Unit::Bytes,
        FAMILIES.total_byte.clone(),
    );
    r.register_with_unit(
        "retina_tcp_received",
        "Number of tcp packets received from dpdk.",
        Unit::Other("pkts".to_string()),
        FAMILIES.tcp_pkt.clone(),
    );
    r.register_with_unit(
        "retina_tcp_received",
        "Number of tcp bytes received from dpdk.",
        Unit::Bytes,
        FAMILIES.tcp_byte.clone(),
    );
    r.register_with_unit(
        "retina_udp_received",
        "Number of udp packets received from dpdk.",
        Unit::Other("pkts".to_string()),
        FAMILIES.udp_pkt.clone(),
    );
    r.register_with_unit(
        "retina_udp_received",
        "Number of udp bytes received from dpdk.",
        Unit::Bytes,
        FAMILIES.udp_byte.clone(),
    );
    r.register(
        "retina_tcp_new_connections",
        "Number of inserts into the tcp session table.",
        FAMILIES.tcp_new_connections.clone(),
    );
    r.register(
        "retina_udp_new_connections",
        "Number of inserts into the udp session table.",
        FAMILIES.udp_new_connections.clone(),
    );
    r.register(
        "retina_idle_cycles",
        "Number of polling loop iterations that had no packet.",
        FAMILIES.idle_cycles.clone(),
    );
    r.register(
        "retina_all_cycles",
        "Number of total polling loop iterations.",
        FAMILIES.total_cycles.clone(),
    );
    r
});

pub(crate) static DPDK_STATS: LazyLock<DpdkPrometheusStats> =
    LazyLock::new(|| DpdkPrometheusStats {
        ingress_pkts: Counter::default(),
        ingress_bits: Counter::default(),
        good_pkts: Counter::default(),
        good_bits: Counter::default(),
        process_bits: Counter::default(),
        process_pkts: Counter::default(),
        hw_dropped_pkts: Counter::default(),
        sw_dropped_pkts: Counter::default(),
    });

pub(crate) struct PerCorePrometheusStats {
    ignored_by_packet_filter_pkt: Counter,
    ignored_by_packet_filter_byte: Counter,
    dropped_middle_of_connection_tcp_pkt: Counter,
    dropped_middle_of_connection_tcp_byte: Counter,
    total_pkt: Counter,
    total_byte: Counter,
    tcp_pkt: Counter,
    tcp_byte: Counter,
    udp_pkt: Counter,
    udp_byte: Counter,
    tcp_new_connections: Counter,
    udp_new_connections: Counter,
    idle_cycles: Counter,
    total_cycles: Counter,
}

pub(crate) fn update_thread_local_stats(core: CoreId) {
    PROMETHEUS.with(|pr| {
        let pr = pr.get_or_init(|| PerCorePrometheusStats {
            ignored_by_packet_filter_pkt: FAMILIES
                .ignored_by_packet_filter_pkt
                .get_or_create(&core)
                .clone(),
            ignored_by_packet_filter_byte: FAMILIES
                .ignored_by_packet_filter_byte
                .get_or_create(&core)
                .clone(),
            dropped_middle_of_connection_tcp_pkt: FAMILIES
                .dropped_middle_of_connection_tcp_pkt
                .get_or_create(&core)
                .clone(),
            dropped_middle_of_connection_tcp_byte: FAMILIES
                .dropped_middle_of_connection_tcp_byte
                .get_or_create(&core)
                .clone(),
            total_pkt: FAMILIES.total_pkt.get_or_create(&core).clone(),
            total_byte: FAMILIES.total_byte.get_or_create(&core).clone(),
            tcp_pkt: FAMILIES.tcp_pkt.get_or_create(&core).clone(),
            tcp_byte: FAMILIES.tcp_byte.get_or_create(&core).clone(),
            udp_pkt: FAMILIES.udp_pkt.get_or_create(&core).clone(),
            udp_byte: FAMILIES.udp_byte.get_or_create(&core).clone(),
            tcp_new_connections: FAMILIES.tcp_new_connections.get_or_create(&core).clone(),
            udp_new_connections: FAMILIES.udp_new_connections.get_or_create(&core).clone(),
            idle_cycles: FAMILIES.idle_cycles.get_or_create(&core).clone(),
            total_cycles: FAMILIES.total_cycles.get_or_create(&core).clone(),
        });
        pr.ignored_by_packet_filter_pkt
            .inc_by(IGNORED_BY_PACKET_FILTER_PKT.get());
        IGNORED_BY_PACKET_FILTER_PKT.set(0);
        pr.ignored_by_packet_filter_byte
            .inc_by(IGNORED_BY_PACKET_FILTER_BYTE.get());
        IGNORED_BY_PACKET_FILTER_BYTE.set(0);
        pr.dropped_middle_of_connection_tcp_pkt
            .inc_by(DROPPED_MIDDLE_OF_CONNECTION_TCP_PKT.get());
        DROPPED_MIDDLE_OF_CONNECTION_TCP_PKT.set(0);
        pr.dropped_middle_of_connection_tcp_byte
            .inc_by(DROPPED_MIDDLE_OF_CONNECTION_TCP_BYTE.get());
        DROPPED_MIDDLE_OF_CONNECTION_TCP_BYTE.set(0);
        pr.total_pkt.inc_by(TOTAL_PKT.get());
        TOTAL_PKT.set(0);
        pr.total_byte.inc_by(TOTAL_BYTE.get());
        TOTAL_BYTE.set(0);
        pr.tcp_pkt.inc_by(TCP_PKT.get());
        TCP_PKT.set(0);
        pr.tcp_byte.inc_by(TCP_BYTE.get());
        TCP_BYTE.set(0);
        pr.udp_pkt.inc_by(UDP_PKT.get());
        UDP_PKT.set(0);
        pr.udp_byte.inc_by(UDP_BYTE.get());
        UDP_BYTE.set(0);
        pr.tcp_new_connections.inc_by(TCP_NEW_CONNECTIONS.get());
        TCP_NEW_CONNECTIONS.set(0);
        pr.udp_new_connections.inc_by(UDP_NEW_CONNECTIONS.get());
        UDP_NEW_CONNECTIONS.set(0);
        pr.idle_cycles.inc_by(IDLE_CYCLES.get());
        IDLE_CYCLES.set(0);
        pr.total_cycles.inc_by(TOTAL_CYCLES.get());
        TOTAL_CYCLES.set(0);
    });
}

pub(crate) async fn serve_req(
    _req: Request<impl Body>,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let mut buffer = String::new();
    prometheus_client::encoding::text::encode(&mut buffer, &STAT_REGISTRY).unwrap();

    let response = Response::builder()
        .status(200)
        .header(
            CONTENT_TYPE,
            "application/openmetrics-text; version=1.0.0; charset=utf-8",
        )
        .body(Full::new(Bytes::from(buffer)))
        .unwrap();

    Ok(response)
}
