use hyper::{header::CONTENT_TYPE, Body, Request, Response};
use prometheus::{
    register_int_counter, Counter, Encoder, Gauge, HistogramVec, IntCounter, Opts, TextEncoder,
};
use std::{
    cell::{Cell, OnceCell},
    sync::LazyLock,
};

use lazy_static::lazy_static;
use prometheus::{labels, opts, register_counter, register_gauge, register_histogram_vec};

use crate::CoreId;

pub struct DpdkPrometheusStats {
    pub ingress_bits: IntCounter,
    pub ingress_pkts: IntCounter,
    pub good_bits: IntCounter,
    pub good_pkts: IntCounter,
    pub process_bits: IntCounter,
    pub process_pkts: IntCounter,
    pub hw_dropped_pkts: IntCounter,
    pub sw_dropped_pkts: IntCounter,
}

pub static DPDK_STATS: LazyLock<DpdkPrometheusStats> = LazyLock::new(|| DpdkPrometheusStats {
    ingress_pkts: register_int_counter!(Opts::new(
        "ingress_pkts",
        "Number of packets received by the NIC."
    ))
    .unwrap(),
    ingress_bits: register_int_counter!(Opts::new(
        "ingress_bits",
        "Number of bits received by the NIC."
    ))
    .unwrap(),
    good_pkts: register_int_counter!(Opts::new(
        "good_pkts",
        "Number of packets received by the DPDK."
    ))
    .unwrap(),
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
    total_byte: IntCounter,
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

pub fn update_thread_local_stats(core_id: CoreId) {
    PROMETHEUS.with(|pr| {
        let pr = pr.get_or_init(|| {
            let core_id = core_id.0 as usize;
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
                total_byte: register_int_counter!(Opts::new(
                    "total_byte",
                    "Number of total bytes received from dpdk."
                )
                .const_label("core", format!("{core_id}")))
                .unwrap(),
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
    let mut buffer = vec![];
    encoder.encode(&metric_families, &mut buffer).unwrap();
    HTTP_BODY_GAUGE.set(buffer.len() as f64);

    let response = Response::builder()
        .status(200)
        .header(CONTENT_TYPE, encoder.format_type())
        .body(Body::from(buffer))
        .unwrap();

    timer.observe_duration();

    Ok(response)
}
