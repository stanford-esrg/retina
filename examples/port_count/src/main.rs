use retina_core::config::load_config;
use retina_core::protocols::packet::{ethernet::*, ipv4::*, ipv6::*, tcp::*, udp::*, Packet};
use retina_core::FiveTuple;
use retina_core::{CoreId, Runtime};
use retina_datatypes::*;
use retina_filtergen::{filter, retina_main};

use std::collections::HashMap;
use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::{AtomicPtr, AtomicUsize, Ordering};
use std::sync::OnceLock;

use array_init::array_init;
use clap::Parser;
use serde::Serialize;

// Argument parsing
#[derive(Parser, Debug)]
struct Args {
    #[clap(short, long, parse(from_os_str), value_name = "FILE")]
    config: PathBuf,
    #[clap(
        short,
        long,
        parse(from_os_str),
        value_name = "FILE",
        default_value = "ports.jsonl"
    )]
    outfile: PathBuf,
}

// Number of cores being used by the runtime; should match config file
// Should be defined at compile-time so that we can use a
// statically-sized array for RESULTS
const NUM_CORES: usize = 16;
// Add 1 for ARR_LEN to avoid overflow; one core is used as main_core
const ARR_LEN: usize = NUM_CORES + 1;

// Port counts for easy tracking
#[derive(Serialize, Default, Debug)]
struct PortCounter {
    pub orig: usize,
    pub resp: usize,
}

impl PortCounter {
    pub fn extend(&mut self, other: &PortCounter) {
        self.orig += other.orig;
        self.resp += other.resp;
    }
}

type PortResults = HashMap<u16, PortCounter>;

// Map [UDP | TCP port] -> number of packets seen (src or dst)
static UDP_PORT_COUNTS_PKT: OnceLock<[AtomicPtr<PortResults>; ARR_LEN]> = OnceLock::new();
static TCP_PORT_COUNTS_PKT: OnceLock<[AtomicPtr<PortResults>; ARR_LEN]> = OnceLock::new();
// Map [UDP | TCP port] -> number of connections seen on that port (src or dst)
static UDP_PORT_COUNTS_CONN: OnceLock<[AtomicPtr<PortResults>; ARR_LEN]> = OnceLock::new();
static TCP_PORT_COUNTS_CONN: OnceLock<[AtomicPtr<PortResults>; ARR_LEN]> = OnceLock::new();
// Map app-layer protocols -> port counters
static PARSED_PORT_COUNTS_PKT: OnceLock<[AtomicPtr<HashMap<String, PortResults>>; ARR_LEN]> =
    OnceLock::new();
static PARSED_PORT_COUNTS_CONN: OnceLock<[AtomicPtr<HashMap<String, PortResults>>; ARR_LEN]> =
    OnceLock::new();

fn init_results() -> [AtomicPtr<PortResults>; ARR_LEN] {
    let mut results = vec![];
    for _ in 0..ARR_LEN {
        results.push(Box::into_raw(Box::new(HashMap::new())));
    }
    array_init(|i| AtomicPtr::new(results[i]))
}

fn init_results_parsed() -> [AtomicPtr<HashMap<String, PortResults>>; ARR_LEN] {
    let mut results = vec![];
    for _ in 0..ARR_LEN {
        results.push(Box::into_raw(Box::new(HashMap::new())));
    }
    array_init(|i| AtomicPtr::new(results[i]))
}

// Accessors
fn udp_port_counts_pkt() -> &'static [AtomicPtr<PortResults>; ARR_LEN] {
    UDP_PORT_COUNTS_PKT.get_or_init(init_results)
}
fn tcp_port_counts_pkt() -> &'static [AtomicPtr<PortResults>; ARR_LEN] {
    TCP_PORT_COUNTS_PKT.get_or_init(init_results)
}
fn udp_port_counts_conn() -> &'static [AtomicPtr<PortResults>; ARR_LEN] {
    UDP_PORT_COUNTS_CONN.get_or_init(init_results)
}
fn tcp_port_counts_conn() -> &'static [AtomicPtr<PortResults>; ARR_LEN] {
    TCP_PORT_COUNTS_CONN.get_or_init(init_results)
}
fn parsed_port_counts_pkt() -> &'static [AtomicPtr<HashMap<String, PortResults>>; ARR_LEN] {
    PARSED_PORT_COUNTS_PKT.get_or_init(init_results_parsed)
}
fn parsed_port_counts_conn() -> &'static [AtomicPtr<HashMap<String, PortResults>>; ARR_LEN] {
    PARSED_PORT_COUNTS_CONN.get_or_init(init_results_parsed)
}

// To make it easier to calculate %s
static UDP_PKT_CNT: AtomicUsize = AtomicUsize::new(0);
static TCP_PKT_CNT: AtomicUsize = AtomicUsize::new(0);
static UDP_CONN_CNT: AtomicUsize = AtomicUsize::new(0);
static TCP_CONN_CNT: AtomicUsize = AtomicUsize::new(0);

// Ensure OnceLocks are all initialized
fn init() {
    let _ = tcp_port_counts_pkt();
    let _ = udp_port_counts_pkt();
    let _ = tcp_port_counts_conn();
    let _ = udp_port_counts_conn();
    let _ = parsed_port_counts_pkt();
    let _ = parsed_port_counts_conn();
}

// Per-packet UDP callback
#[filter("udp")]
fn udp_cb(mbuf: &ZcFrame, core_id: &CoreId) {
    let mut src_port = None;
    let mut dst_port = None;
    if let Ok(eth) = &Packet::parse_to::<Ethernet>(mbuf) {
        if let Ok(ipv4) = &Packet::parse_to::<Ipv4>(eth) {
            if let Ok(udp) = &Packet::parse_to::<Udp>(ipv4) {
                src_port = Some(udp.src_port());
                dst_port = Some(udp.dst_port());
            }
        } else if let Ok(ipv6) = &Packet::parse_to::<Ipv6>(eth) {
            if let Ok(udp) = &Packet::parse_to::<Udp>(ipv6) {
                src_port = Some(udp.src_port());
                dst_port = Some(udp.dst_port());
            }
        }
    }
    let ptr = udp_port_counts_pkt()[core_id.raw() as usize].load(Ordering::Relaxed);
    let dict = unsafe { &mut *ptr };
    let entry = dict
        .entry(src_port.unwrap())
        .or_insert(PortCounter::default());
    entry.orig += 1;
    let entry = dict
        .entry(dst_port.unwrap())
        .or_insert(PortCounter::default());
    entry.resp += 1;
    UDP_PKT_CNT.fetch_add(1, Ordering::Relaxed);
}

// Per-packet TCP callback
#[filter("tcp")]
fn tcp_cp(mbuf: &ZcFrame, core_id: &CoreId) {
    let mut dst_port = None;
    let mut src_port = None;
    if let Ok(eth) = &Packet::parse_to::<Ethernet>(mbuf) {
        if let Ok(ipv4) = &Packet::parse_to::<Ipv4>(eth) {
            if let Ok(tcp) = &Packet::parse_to::<Tcp>(ipv4) {
                src_port = Some(tcp.src_port());
                dst_port = Some(tcp.dst_port());
            }
        } else if let Ok(ipv6) = &Packet::parse_to::<Ipv6>(eth) {
            if let Ok(tcp) = &Packet::parse_to::<Tcp>(ipv6) {
                src_port = Some(tcp.src_port());
                dst_port = Some(tcp.dst_port());
            }
        }
    }
    let ptr = tcp_port_counts_pkt()[core_id.raw() as usize].load(Ordering::Relaxed);
    let dict = unsafe { &mut *ptr };
    let entry = dict
        .entry(src_port.unwrap())
        .or_insert(PortCounter::default());
    entry.orig += 1;
    let entry = dict
        .entry(dst_port.unwrap())
        .or_insert(PortCounter::default());
    entry.resp += 1;
    TCP_PKT_CNT.fetch_add(1, Ordering::Relaxed);
}

// Per-connection UDP callback
#[filter("udp")]
fn udp_conn_cb(five_tuple: &FiveTuple, core_id: &CoreId) {
    let dst_port = five_tuple.resp.port();
    let src_port = five_tuple.orig.port();
    let ptr = udp_port_counts_conn()[core_id.raw() as usize].load(Ordering::Relaxed);
    let dict = unsafe { &mut *ptr };
    let entry = dict.entry(src_port).or_insert(PortCounter::default());
    entry.orig += 1;
    let entry = dict.entry(dst_port).or_insert(PortCounter::default());
    entry.resp += 1;
    UDP_CONN_CNT.fetch_add(1, Ordering::Relaxed);
}

// Per-packet TCP callback
#[filter("tcp")]
fn tcp_conn_cb(five_tuple: &FiveTuple, core_id: &CoreId) {
    let dst_port = five_tuple.resp.port();
    let src_port = five_tuple.orig.port();
    let ptr = tcp_port_counts_conn()[core_id.raw() as usize].load(Ordering::Relaxed);
    let dict = unsafe { &mut *ptr };
    let entry = dict.entry(src_port).or_insert(PortCounter::default());
    entry.orig += 1;
    let entry = dict.entry(dst_port).or_insert(PortCounter::default());
    entry.resp += 1;
    TCP_CONN_CNT.fetch_add(1, Ordering::Relaxed);
}

// Per-connection application-layer callbacks

fn insert_parsed_results(
    pkts: &PktCount,
    core_id: &CoreId,
    key: String,
    dst_port: u16,
    src_port: u16,
) {
    let ptr = parsed_port_counts_conn()[core_id.raw() as usize].load(Ordering::Relaxed);
    let dict = unsafe { &mut *ptr };
    let entry = dict
        .entry(key.clone())
        .or_insert(HashMap::new())
        .entry(src_port)
        .or_insert(PortCounter::default());
    entry.orig += 1;
    let entry = dict
        .entry(key.clone())
        .or_insert(HashMap::new())
        .entry(dst_port)
        .or_insert(PortCounter::default());
    entry.resp += 1;

    let ptr = parsed_port_counts_pkt()[core_id.raw() as usize].load(Ordering::Relaxed);
    let dict = unsafe { &mut *ptr };
    let entry = dict
        .entry(key.clone())
        .or_insert(HashMap::new())
        .entry(src_port)
        .or_insert(PortCounter::default());
    entry.orig += pkts.raw();
    let entry = dict
        .entry(key)
        .or_insert(HashMap::new())
        .entry(dst_port)
        .or_insert(PortCounter::default());
    entry.resp += pkts.raw();
}

#[filter("dns and udp")]
fn dns_udp_cb(five_tuple: &FiveTuple, pkts: &PktCount, core_id: &CoreId) {
    let dst_port = five_tuple.resp.port();
    let src_port = five_tuple.orig.port();
    insert_parsed_results(pkts, core_id, String::from("dns_udp"), dst_port, src_port);
}

#[filter("dns and tcp")]
fn dns_tcp_cb(five_tuple: &FiveTuple, pkts: &PktCount, core_id: &CoreId) {
    let dst_port = five_tuple.resp.port();
    let src_port = five_tuple.orig.port();
    insert_parsed_results(pkts, core_id, String::from("dns_tcp"), dst_port, src_port);
}

#[filter("http")]
fn http_cb(five_tuple: &FiveTuple, pkts: &PktCount, core_id: &CoreId) {
    let dst_port = five_tuple.resp.port();
    let src_port = five_tuple.orig.port();
    insert_parsed_results(pkts, core_id, String::from("http"), dst_port, src_port);
}

#[filter("tls")]
fn tls_cb(five_tuple: &FiveTuple, pkts: &PktCount, core_id: &CoreId) {
    let dst_port = five_tuple.resp.port();
    let src_port = five_tuple.orig.port();
    insert_parsed_results(pkts, core_id, String::from("tls"), dst_port, src_port);
}

#[filter("quic")]
fn quic_cb(five_tuple: &FiveTuple, pkts: &PktCount, core_id: &CoreId) {
    let dst_port = five_tuple.resp.port();
    let src_port = five_tuple.orig.port();
    insert_parsed_results(pkts, core_id, String::from("quic"), dst_port, src_port);
}

// Combine results for easy serialization
#[derive(Serialize, Default)]
struct CombinedResults {
    pub udp_pkts: PortResults,
    pub tcp_pkts: PortResults,
    pub udp_conns: PortResults,
    pub tcp_conns: PortResults,
    pub parsed_conns: HashMap<String, PortResults>,
    pub parsed_pkts: HashMap<String, PortResults>,
    pub udp_pkt_count: usize,
    pub udp_conn_count: usize,
    pub tcp_pkt_count: usize,
    pub tcp_conn_count: usize,
}

// TODO combine results with `extend` without weird borrowing stuff
fn combine_results(outfile: &PathBuf) {
    let mut results = CombinedResults::default();
    for core_id in 0..ARR_LEN {
        // TCP per-port packet counts
        let ptr = tcp_port_counts_pkt()[core_id].load(Ordering::SeqCst);
        for (key, value) in unsafe { &*ptr } {
            results
                .tcp_pkts
                .entry(*key)
                .or_insert(PortCounter::default())
                .extend(value);
        }

        // TCP per-port conn counts
        let ptr = tcp_port_counts_conn()[core_id].load(Ordering::SeqCst);
        for (key, value) in unsafe { &*ptr } {
            results
                .tcp_conns
                .entry(*key)
                .or_insert(PortCounter::default())
                .extend(value);
        }

        // UDP per-port packet counts
        let ptr = udp_port_counts_pkt()[core_id].load(Ordering::SeqCst);
        for (key, value) in unsafe { &*ptr } {
            results
                .udp_pkts
                .entry(*key)
                .or_insert(PortCounter::default())
                .extend(value);
        }

        // UDP per-port conn counts
        let ptr = udp_port_counts_conn()[core_id].load(Ordering::SeqCst);
        for (key, value) in unsafe { &*ptr } {
            results
                .udp_conns
                .entry(*key)
                .or_insert(PortCounter::default())
                .extend(value);
        }

        // Session per-port pkt counts
        let ptr = parsed_port_counts_pkt()[core_id].load(Ordering::Relaxed);
        for (key, value) in unsafe { &*ptr } {
            let entry = results
                .parsed_pkts
                .entry(key.clone())
                .or_insert(PortResults::default());

            for (port, counters) in value {
                entry
                    .entry(*port)
                    .or_insert(PortCounter::default())
                    .extend(counters);
            }
        }

        // Session per-port conn counts
        let ptr = parsed_port_counts_conn()[core_id].load(Ordering::Relaxed);
        for (key, value) in unsafe { &*ptr } {
            let entry = results
                .parsed_conns
                .entry(key.clone())
                .or_insert(PortResults::default());
            for (port, counters) in value {
                entry
                    .entry(*port)
                    .or_insert(PortCounter::default())
                    .extend(counters);
            }
        }
    }
    results.udp_pkt_count = UDP_PKT_CNT.load(Ordering::SeqCst);
    results.tcp_pkt_count = TCP_PKT_CNT.load(Ordering::SeqCst);
    results.udp_conn_count = UDP_CONN_CNT.load(Ordering::SeqCst);
    results.tcp_conn_count = TCP_CONN_CNT.load(Ordering::SeqCst);
    let mut file = std::fs::File::create(outfile).unwrap();
    let results = serde_json::to_string(&results).unwrap();
    file.write_all(results.as_bytes()).unwrap();
}

#[retina_main(9)]
fn main() {
    init();
    let args = Args::parse();
    let config = load_config(&args.config);
    let cores = config.get_all_rx_core_ids();
    let num_cores = cores.len();
    if num_cores > NUM_CORES {
        panic!(
            "Compile-time NUM_CORES ({}) must be <= num cores ({}) in config file",
            NUM_CORES, num_cores
        );
    }
    if cores.len() > 1 && !cores.windows(2).all(|w| w[1].raw() - w[0].raw() == 1) {
        panic!("Cores in config file should be consecutive for zero-lock indexing");
    }
    if cores[0].raw() > 1 {
        panic!("RX core IDs should start at 0 or 1");
    }
    let mut runtime: Runtime<SubscribedWrapper> = Runtime::new(config, filter).unwrap();
    runtime.run();
    combine_results(&args.outfile);
    println!(
        "Got {} tcp, {} udp packets; {} tcp, {} udp conns",
        TCP_PKT_CNT.load(Ordering::SeqCst),
        UDP_PKT_CNT.load(Ordering::SeqCst),
        TCP_CONN_CNT.load(Ordering::SeqCst),
        UDP_CONN_CNT.load(Ordering::SeqCst)
    );
}
