use array_init::array_init;
use retina_core::config::load_config;
use retina_core::{CoreId, Runtime};
use retina_datatypes::*;
use retina_filtergen::subscription;
use std::sync::atomic::{AtomicPtr, Ordering};

use clap::Parser;
use lazy_static::lazy_static;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::PathBuf;

// Number of cores being used by the runtime; should match config file
// Should be defined at compile-time so that we can use a
// statically-sized array for RESULTS
const NUM_CORES: usize = 16;
// Add 1 for ARR_LEN to avoid overflow; one core is used as main_core
const ARR_LEN: usize = NUM_CORES + 1;
// Temporary per-core files
const OUTFILE_PREFIX: &str = "filter_stats_";

lazy_static! {
    static ref RESULTS: [AtomicPtr<BufWriter<File>>; ARR_LEN] = {
        let mut results = vec![];
        for core_id in 0..ARR_LEN {
            let file_name = String::from(OUTFILE_PREFIX) + &format!("{}", core_id) + ".jsonl";
            let core_wtr = BufWriter::new(File::create(&file_name).unwrap());
            let core_wtr = Box::into_raw(Box::new(core_wtr));
            results.push(core_wtr);
        }
        array_init(|i| AtomicPtr::new(results[i].clone()))
    };
}

fn init() {
    println!("Initializing {} results", RESULTS.len());
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

fn write_result(key: &str, value: String, core_id: &CoreId) {
    if value.is_empty() {
        return;
    } // Would it be helpful to count these?
    let with_proto = format!("\n{}: {}", key, value);
    let ptr = RESULTS[core_id.raw() as usize].load(Ordering::Relaxed);
    let wtr = unsafe { &mut *ptr };
    wtr.write_all(with_proto.as_bytes()).unwrap();
}

fn dns_cb(dns: &DnsTransaction, core_id: &CoreId, filter_str: &FilterStr) {
    let query_domain = (*dns).query_domain().to_string();
    write_result(*filter_str, query_domain, core_id);
}

fn http_cb(http: &HttpTransaction, core_id: &CoreId, filter_str: &FilterStr) {
    let uri = (*http).uri().to_string();
    write_result(*filter_str, uri, core_id);
}

fn tls_cb(tls: &TlsHandshake, core_id: &CoreId, filter_str: &FilterStr) {
    let sni = (*tls).sni().to_string();
    write_result(*filter_str, sni, core_id);
}

#[allow(dead_code)]
fn quic_cb(quic: &QuicStream, core_id: &CoreId, filter_str: &FilterStr) {
    let sni = (*quic).tls.sni().to_string();
    write_result(*filter_str, sni, core_id);
}

fn packet_cb(_frame: &ZcFrame, core_id: &CoreId, filter_str: &FilterStr) {
    write_result(*filter_str, String::from(""), core_id);
}

fn conn_cb(core_id: &CoreId, filter_str: &FilterStr) {
    write_result(*filter_str, String::from(""), core_id);
}

fn combine_results(outfile: &PathBuf) {
    println!("Combining results from {} cores...", NUM_CORES);
    let mut results = Vec::new();
    for core_id in 0..ARR_LEN {
        let fp = String::from(OUTFILE_PREFIX) + &format!("{}", core_id) + ".jsonl";
        let content = std::fs::read(fp.clone()).unwrap();
        results.extend_from_slice(&content);
        std::fs::remove_file(fp).unwrap();
    }
    let mut file = std::fs::File::create(outfile).unwrap();
    file.write_all(&results).unwrap();
}

#[subscription("./examples/filter_stats/spec.toml")]
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
