use http_body_util::Full;
use hyper::{
    body::{Body, Bytes},
    header::CONTENT_TYPE,
    Request, Response,
};
use prometheus_client::{
    encoding::EncodeLabelSet,
    metrics::family::Family,
    registry::{Registry, Unit},
};
use std::{
    cell::{Cell, OnceCell},
    fmt::Write,
    sync::LazyLock,
};

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
pub struct Families {
    ignored_by_packet_filter_pkt: Family<CoreId, prometheus_client::metrics::counter::Counter>,
    ignored_by_packet_filter_byte: Family<CoreId, prometheus_client::metrics::counter::Counter>,
    dropped_middle_of_connection_tcp_pkt:
        Family<CoreId, prometheus_client::metrics::counter::Counter>,
    dropped_middle_of_connection_tcp_byte:
        Family<CoreId, prometheus_client::metrics::counter::Counter>,
    total_pkt: Family<CoreId, prometheus_client::metrics::counter::Counter>,
    total_byte: Family<CoreId, prometheus_client::metrics::counter::Counter>,
    idle_cycles: Family<CoreId, prometheus_client::metrics::counter::Counter>,
    total_cycles: Family<CoreId, prometheus_client::metrics::counter::Counter>,
}

pub static FAMILIES: LazyLock<Families> = LazyLock::new(Families::default);

pub struct DpdkPrometheusStats {
    pub ingress_bits: prometheus_client::metrics::counter::Counter,
    pub ingress_pkts: prometheus_client::metrics::counter::Counter,
    pub good_bits: prometheus_client::metrics::counter::Counter,
    pub good_pkts: prometheus_client::metrics::counter::Counter,
    pub process_bits: prometheus_client::metrics::counter::Counter,
    pub process_pkts: prometheus_client::metrics::counter::Counter,
    pub hw_dropped_pkts: prometheus_client::metrics::counter::Counter,
    pub sw_dropped_pkts: prometheus_client::metrics::counter::Counter,
}

pub static STAT_REGISTRY: LazyLock<Registry> = LazyLock::new(|| {
    let mut r = Registry::default();
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

pub static DPDK_STATS: LazyLock<DpdkPrometheusStats> = LazyLock::new(|| DpdkPrometheusStats {
    ingress_pkts: prometheus_client::metrics::counter::Counter::default(),
    ingress_bits: prometheus_client::metrics::counter::Counter::default(),
    good_pkts: prometheus_client::metrics::counter::Counter::default(),
    good_bits: prometheus_client::metrics::counter::Counter::default(),
    process_bits: prometheus_client::metrics::counter::Counter::default(),
    process_pkts: prometheus_client::metrics::counter::Counter::default(),
    hw_dropped_pkts: prometheus_client::metrics::counter::Counter::default(),
    sw_dropped_pkts: prometheus_client::metrics::counter::Counter::default(),
});

struct PerCorePrometheusStats {
    ignored_by_packet_filter_pkt: prometheus_client::metrics::counter::Counter,
    ignored_by_packet_filter_byte: prometheus_client::metrics::counter::Counter,
    dropped_middle_of_connection_tcp_pkt: prometheus_client::metrics::counter::Counter,
    dropped_middle_of_connection_tcp_byte: prometheus_client::metrics::counter::Counter,
    total_pkt: prometheus_client::metrics::counter::Counter,
    total_byte: prometheus_client::metrics::counter::Counter,
    idle_cycles: prometheus_client::metrics::counter::Counter,
    total_cycles: prometheus_client::metrics::counter::Counter,
}

thread_local! {
    pub static IGNORED_BY_PACKET_FILTER_PKT: Cell<u64> = const { Cell::new(0) };
    pub static IGNORED_BY_PACKET_FILTER_BYTE: Cell<u64> = const { Cell::new(0) };
    pub static DROPPED_MIDDLE_OF_CONNECTION_TCP_PKT: Cell<u64> = const { Cell::new(0) };
    pub static DROPPED_MIDDLE_OF_CONNECTION_TCP_BYTE: Cell<u64> = const { Cell::new(0) };
    pub static TOTAL_PKT: Cell<u64> = const { Cell::new(0) };
    pub static TOTAL_BYTE: Cell<u64> = const { Cell::new(0) };
    pub static IDLE_CYCLES: Cell<u64> = const { Cell::new(0) };
    pub static TOTAL_CYCLES: Cell<u64> = const { Cell::new(0) };
    pub static PROMETHEUS: OnceCell<PerCorePrometheusStats> = const { OnceCell::new() };
}

pub trait StatExt: Sized {
    fn inc(&'static self) {
        self.inc_by(1);
    }
    fn inc_by(&'static self, val: u64);
}

impl StatExt for std::thread::LocalKey<Cell<u64>> {
    fn inc_by(&'static self, val: u64) {
        self.set(self.get() + val);
    }
}

pub fn update_thread_local_stats(core: CoreId) {
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
        pr.idle_cycles.inc_by(IDLE_CYCLES.get());
        IDLE_CYCLES.set(0);
        pr.total_cycles.inc_by(TOTAL_CYCLES.get());
        TOTAL_CYCLES.set(0);
    });
}

pub async fn serve_req(_req: Request<impl Body>) -> Result<Response<Full<Bytes>>, hyper::Error> {
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
