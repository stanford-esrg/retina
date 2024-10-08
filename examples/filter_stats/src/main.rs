use retina_core::config::load_config;
use retina_core::{CoreId, Runtime};
use retina_datatypes::*;
use retina_filtergen::subscription;
use serde::Serialize;

use std::collections::HashMap;
use std::io::Write;
use std::sync::atomic::{AtomicPtr, AtomicUsize, Ordering};

use array_init::array_init;
use clap::Parser;
use std::path::PathBuf;
use std::sync::OnceLock;

const NUM_CORES: usize = 16;
const ARR_LEN: usize = NUM_CORES + 1;

#[derive(Serialize)]
struct ConnStats {
    pub total_pkts: usize,
    pub total_bytes: usize,
    pub conn_count: Option<usize>,
}

impl ConnStats {
    pub fn new() -> Self {
        Self {
            total_pkts: 0,
            total_bytes: 0,
            conn_count: Some(0),
        }
    }

    pub fn update(&mut self, pkts: &PktCount, bytes: &ByteCount) {
        self.conn_count.map(|cnt| cnt + 1);
        self.total_pkts += pkts.pkt_count;
        self.total_bytes += bytes.byte_count;
    }

    pub fn combine(&mut self, other: &ConnStats) {
        self.total_pkts += other.total_pkts;
        self.total_bytes += other.total_bytes;
        self.conn_count.map(|cnt| cnt + other.conn_count.unwrap());
    }
}

static RESULTS: OnceLock<[AtomicPtr<HashMap<String, ConnStats>>; ARR_LEN]> = OnceLock::new();
static BYTES: OnceLock<[AtomicUsize; ARR_LEN]> = OnceLock::new();
static PKTS: OnceLock<[AtomicUsize; ARR_LEN]> = OnceLock::new();

fn results() -> &'static [AtomicPtr<HashMap<String, ConnStats>>; ARR_LEN] {
    RESULTS.get_or_init( || {
        array_init(|_| AtomicPtr::new(Box::into_raw(Box::new(HashMap::new()))))
    })
}

fn bytes() -> &'static [AtomicUsize; ARR_LEN] {
    BYTES.get_or_init( || {
        array_init(|_| AtomicUsize::new(0))
    })
}

fn pkts() -> &'static [AtomicUsize; ARR_LEN] {
    PKTS.get_or_init( || {
        array_init(|_| AtomicUsize::new(0))
    })
}

fn init() {
    let _ = results();
    let _ = bytes();
    let _ = pkts();
}

#[derive(Parser, Debug)]
struct Args {
    #[clap(short, long, parse(from_os_str), value_name = "FILE")]
    config: PathBuf,
    #[clap(
        short,
        long,
        parse(from_os_str),
        value_name = "FILE",
        default_value = "filter_stats.jsonl"
    )]
    outfile: PathBuf,
}

fn record_conn(pkts: &PktCount, bytes: &ByteCount, core_id: &CoreId, filter_str: &FilterStr) {
    let ptr = results()[core_id.raw() as usize].load(Ordering::Relaxed);
    let dict = unsafe { &mut *ptr };
    (*dict
        .entry(String::from(*filter_str))
        .or_insert(ConnStats::new()))
    .update(pkts, bytes);
}

fn record_pkt(mbuf: &ZcFrame, core_id: &CoreId) {
    pkts()[core_id.raw() as usize].fetch_add(1, Ordering::Relaxed);
    bytes()[core_id.raw() as usize].fetch_add(mbuf.data_len(), Ordering::Relaxed);
}

fn combine_results(outfile: &PathBuf) {
    let mut outp = HashMap::new();
    for core_id in 0..ARR_LEN {
        let ptr = results()[core_id as usize].load(Ordering::SeqCst);
        let dict = unsafe { &mut *ptr };
        for (fil, stats) in dict.iter() {
            outp
                .entry(fil.clone())
                .or_insert(ConnStats::new())
                .combine(stats);
        }
    }

    let total_pkts = pkts().iter().map(|cnt| cnt.load(Ordering::SeqCst)).sum();
    let total_bytes = bytes().iter().map(|cnt| cnt.load(Ordering::SeqCst)).sum();

    let mut all_pkts = ConnStats::new();
    all_pkts.total_pkts = total_pkts;
    all_pkts.total_bytes = total_bytes;
    outp.insert("all_traffic".into(), all_pkts);

    let mut file = std::fs::File::create(outfile).unwrap();
    let outp = serde_json::to_string(&outp).unwrap();
    file.write_all(outp.as_bytes()).unwrap();
}

#[subscription("/home/tcr6/retina/examples/filter_stats/spec.toml")]
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
}
