use hyper::{header::CONTENT_TYPE, Body, Request, Response};
use prometheus::{
    register_int_counter, Counter, Encoder, Gauge, HistogramVec, IntCounter, Opts, TextEncoder,
};
use prometheus_client::{
    encoding::EncodeLabelSet,
    metrics::family::Family,
    registry::{Registry, Unit},
};
use std::{
    cell::{Cell, OnceCell},
    fmt::Write,
    sync::{LazyLock, Mutex},
};

use lazy_static::lazy_static;
use prometheus::{labels, opts, register_counter, register_gauge, register_histogram_vec};

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
    total_byte: Family<CoreId, prometheus_client::metrics::counter::Counter>,
}

pub static FAMILIES: LazyLock<Families> = LazyLock::new(Families::default);

pub struct DpdkPrometheusStats {
    pub ingress_bits: prometheus_client::metrics::counter::Counter,
    pub ingress_pkts: IntCounter,
    pub good_bits: IntCounter,
    pub good_pkts: prometheus_client::metrics::counter::Counter,
    pub process_bits: IntCounter,
    pub process_pkts: IntCounter,
    pub hw_dropped_pkts: IntCounter,
    pub sw_dropped_pkts: IntCounter,
}

pub static STAT_REGISTRY: LazyLock<Registry> = LazyLock::new(|| {
    let mut r = Registry::default();
    r.register_with_unit(
        "ingress_bits",
        "Number of bits received by the NIC.",
        Unit::Bytes,
        DPDK_STATS.ingress_bits.clone(),
    );
    r.register(
        "good_pkts",
        "Number of packets received by the DPDK.",
        DPDK_STATS.good_pkts.clone(),
    );
    r.register_with_unit(
        "total_byte",
        "Number of total bytes received from dpdk.",
        Unit::Bytes,
        FAMILIES.total_byte.clone(),
    );
    r
});

pub static DPDK_STATS: LazyLock<DpdkPrometheusStats> = LazyLock::new(|| DpdkPrometheusStats {
    ingress_pkts: register_int_counter!(Opts::new(
        "ingress_pkts",
        "Number of packets received by the NIC."
    ))
    .unwrap(),
    ingress_bits: prometheus_client::metrics::counter::Counter::default(),
    good_pkts: prometheus_client::metrics::counter::Counter::default(),
    good_bits: register_int_counter!(Opts::new(
        "good_bits",
        "Number of bits received by the DPDK."
    ))
    .unwrap(),
    process_pkts: register_int_counter!(Opts::new(
        "process_pkts",
        "Number of packets received by the retina workers."
    ))
    .unwrap(),
    process_bits: register_int_counter!(Opts::new(
        "process_bits",
        "Number of bits received by the retina workers."
    ))
    .unwrap(),
    hw_dropped_pkts: register_int_counter!(Opts::new(
        "hw_dropped_pkts",
        "Number of packets dropped by hardware."
    ))
    .unwrap(),
    sw_dropped_pkts: register_int_counter!(Opts::new(
        "sw_dropped_pkts",
        "Number of packets dropped by software."
    ))
    .unwrap(),
});

struct PerCorePrometheusStats {
    ignored_by_packet_filter_pkt: IntCounter,
    ignored_by_packet_filter_byte: IntCounter,
    dropped_middle_of_connection_tcp_pkt: IntCounter,
    dropped_middle_of_connection_tcp_byte: IntCounter,
    total_pkt: IntCounter,
    total_byte: prometheus_client::metrics::counter::Counter,
    idle_cycles: IntCounter,
    total_cycles: IntCounter,
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
        let pr = pr.get_or_init(|| {
            let core_id = core.0 as usize;
            PerCorePrometheusStats {
                ignored_by_packet_filter_pkt: register_int_counter!(Opts::new(
                    "ignored_by_packet_filter_pkt",
                    "Number of packets ignored by packet filter."
                )
                .const_label("core", format!("{core_id}")))
                .unwrap(),
                ignored_by_packet_filter_byte: register_int_counter!(Opts::new(
                    "ignored_by_packet_filter_byte",
                    "Number of bytes ignored by packet filter."
                )
                .const_label("core", format!("{core_id}")))
                .unwrap(),
                dropped_middle_of_connection_tcp_pkt: register_int_counter!(Opts::new(
                    "dropped_middle_of_connection_tcp_pkt",
                    "Number of packets dropped due missing SYN packet."
                )
                .const_label("core", format!("{core_id}")))
                .unwrap(),
                dropped_middle_of_connection_tcp_byte: register_int_counter!(Opts::new(
                    "dropped_middle_of_connection_tcp_byte",
                    "Number of bytes dropped due missing SYN packet."
                )
                .const_label("core", format!("{core_id}")))
                .unwrap(),
                total_pkt: register_int_counter!(Opts::new(
                    "total_pkt",
                    "Number of total packets received from dpdk."
                )
                .const_label("core", format!("{core_id}")))
                .unwrap(),
                total_byte: FAMILIES.total_byte.get_or_create(&core).clone(),
                idle_cycles: register_int_counter!(Opts::new(
                    "idle_cycles",
                    "Number of polling loop iterations that had no packet."
                )
                .const_label("core", format!("{core_id}")))
                .unwrap(),
                total_cycles: register_int_counter!(Opts::new(
                    "total_cycles",
                    "Number of total polling loop iterations."
                )
                .const_label("core", format!("{core_id}")))
                .unwrap(),
            }
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

lazy_static! {
    static ref HTTP_COUNTER: Counter = register_counter!(opts!(
        "example_http_requests_total",
        "Number of HTTP requests made.",
        labels! {"handler" => "all",}
    ))
    .unwrap();
    static ref HTTP_BODY_GAUGE: Gauge = register_gauge!(opts!(
        "example_http_response_size_bytes",
        "The HTTP response sizes in bytes.",
        labels! {"handler" => "all",}
    ))
    .unwrap();
    static ref HTTP_REQ_HISTOGRAM: HistogramVec = register_histogram_vec!(
        "example_http_request_duration_seconds",
        "The HTTP request latencies in seconds.",
        &["handler"]
    )
    .unwrap();
}

pub async fn serve_req(_req: Request<Body>) -> Result<Response<Body>, hyper::Error> {
    let encoder = TextEncoder::new();

    HTTP_COUNTER.inc();
    let timer = HTTP_REQ_HISTOGRAM.with_label_values(&["all"]).start_timer();

    let metric_families = prometheus::gather();
    let mut buffer = String::new();
    prometheus_client::encoding::text::encode(&mut buffer, &STAT_REGISTRY).unwrap();
    // encoder.encode(&metric_families, &mut buffer).unwrap();
    HTTP_BODY_GAUGE.set(buffer.len() as f64);

    let response = Response::builder()
        .status(200)
        .header(
            CONTENT_TYPE,
            "application/openmetrics-text; version=1.0.0; charset=utf-8",
        )
        .body(Body::from(buffer))
        .unwrap();

    timer.observe_duration();

    Ok(response)
}
