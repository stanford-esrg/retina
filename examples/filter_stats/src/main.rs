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
use lazy_static::lazy_static;
use std::path::PathBuf;

const NUM_CORES: usize = 16;
const ARR_LEN: usize = NUM_CORES + 1;

#[derive(Serialize)]
struct ConnStats {
    pub total_pkts: usize,
    pub total_bytes: usize,
    pub avg_duration_ms: u128,
    pub max_duration_ms: u128,
    pub min_duration_ms: u128,
    pub conn_count: usize,
    #[serde(skip_serializing)]
    pub init: bool,
}

impl ConnStats {
    pub fn new() -> Self {
        Self {
            total_pkts: 0,
            total_bytes: 0,
            avg_duration_ms: 0,
            max_duration_ms: 0,
            min_duration_ms: 0,
            conn_count: 0,
            init: false,
        }
    }

    pub fn update(&mut self, conn: &ByteCounter) {
        self.conn_count += 1;
        self.total_pkts += conn.pkt_count;
        self.total_bytes += conn.byte_count;
        let duration = conn.duration_ms();
        // avg = avg + (new - avg) / count
        self.avg_duration_ms += duration / self.conn_count as u128;
        self.avg_duration_ms -= self.avg_duration_ms / self.conn_count as u128;

        if duration > self.max_duration_ms {
            self.max_duration_ms = duration;
        }
        if duration < self.min_duration_ms || !self.init {
            self.min_duration_ms = duration;
            self.init = true;
        }
    }

    pub fn combine(&mut self, other: &ConnStats) {
        self.total_pkts += other.total_pkts;
        self.total_bytes += other.total_bytes;
        self.conn_count += other.conn_count;

        self.avg_duration_ms = (self.avg_duration_ms * self.conn_count as u128 +
                                other.avg_duration_ms * other.conn_count as u128) /
                                (self.conn_count + other.conn_count) as u128;

        if other.max_duration_ms > self.max_duration_ms {
            self.max_duration_ms = other.max_duration_ms;
        }
        if other.min_duration_ms < self.min_duration_ms {
            self.min_duration_ms = other.min_duration_ms;
        }
    }
}

fn init_results() -> [AtomicPtr<HashMap<String, ConnStats>>; ARR_LEN] {
    array_init(|_| AtomicPtr::new(Box::into_raw(Box::new(HashMap::new()))))
}

lazy_static! {
    static ref RESULTS: [AtomicPtr<HashMap<String, ConnStats>>; ARR_LEN] = init_results();
    static ref BYTES: [AtomicUsize; ARR_LEN] = {
        array_init(|_| AtomicUsize::new(0))
    };
    static ref PKTS: [AtomicUsize; ARR_LEN] = {
        array_init(|_| AtomicUsize::new(0))
    };
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

fn record_conn(conn: &ByteCounter, core_id: &CoreId, filter_str: &FilterStr) {
    let ptr = RESULTS[core_id.raw() as usize].load(Ordering::Relaxed);
    let dict = unsafe { &mut *ptr };
    (*dict.entry(String::from(*filter_str)).or_insert(ConnStats::new())).update(conn);
}

fn record_pkt(mbuf: &ZcFrame, core_id: &CoreId) {
    PKTS[core_id.raw() as usize].fetch_add(1, Ordering::Relaxed);
    BYTES[core_id.raw() as usize].fetch_add(mbuf.data_len(), Ordering::Relaxed);
}

fn combine_results(outfile: &PathBuf) {
    let mut results = HashMap::new();
    for core_id in 0..ARR_LEN {
        let ptr = RESULTS[core_id as usize].load(Ordering::SeqCst);
        let dict = unsafe { &mut *ptr };
        for (fil, stats) in dict.iter() {
            results.entry(fil.clone()).or_insert(ConnStats::new()).combine(stats);
        }
    }

    let total_pkts = PKTS.iter()
                         .map(|cnt| cnt.load(Ordering::SeqCst)).sum();
    let total_bytes = BYTES.iter()
                           .map(|cnt| cnt.load(Ordering::SeqCst)).sum();

    let mut all_pkts = ConnStats::new();
    all_pkts.total_pkts = total_pkts;
    all_pkts.total_bytes = total_bytes;
    results.insert("all_traffic".into(), all_pkts);

    let mut file = std::fs::File::create(outfile).unwrap();
    let results = serde_json::to_string(&results).unwrap();
    file.write_all(results.as_bytes()).unwrap();
}

#[subscription("/home/tcr6/retina/examples/filter_stats/spec.toml")]
fn main() {
    let args = Args::parse();
    let config = load_config(&args.config);
    let cores = config.get_all_core_ids();
    let num_cores = cores.len();
    if num_cores > ARR_LEN {
        panic!(
            "Compile-time NUM_CORES ({}) must be <= num cores ({}) in config file",
            NUM_CORES, num_cores
        );
    }
    if cores.len() > 1 && !cores.windows(2).all(|w| w[1].raw() - w[0].raw() == 1) {
        panic!("Cores in config file should be consecutive for zero-lock indexing");
    }
    let mut runtime: Runtime<SubscribedWrapper> = Runtime::new(config, filter).unwrap();
    runtime.run();
    combine_results(&args.outfile);
}
