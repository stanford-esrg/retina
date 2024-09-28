use retina_core::config::load_config;
use retina_core::{CoreId, Runtime};
use retina_datatypes::*;
use retina_filtergen::subscription;
use std::sync::atomic::{AtomicPtr, Ordering};
use array_init::array_init;
use std::collections::HashMap;

use clap::Parser;
use std::path::PathBuf;
use lazy_static::lazy_static;
use std::io::{BufWriter, Write};
use std::fs::File;

const NUM_CORES: usize = 16;
const OUTFILE_PREFIX: &str = "websites_";

lazy_static! {
    static ref PROTOS: Vec<String> = vec![String::from("dns"), String::from("http"), String::from("quic"), String::from("tls")];

    static ref RESULTS: [AtomicPtr<BufWriter<File>>; NUM_CORES] = {
        let mut results = vec![];
        for core_id in 0..NUM_CORES {
            let file_name = String::from(OUTFILE_PREFIX) + &format!("{}", core_id) + ".jsonl";
            let mut core_wtr = BufWriter::new(
                    File::create(&file_name).unwrap()
                );
            core_wtr.write(b"[\n[\"start\", \"start\"]").unwrap();
            let core_wtr = Box::into_raw(Box::new(core_wtr));
            results.push(core_wtr);
        }
        array_init(|i| AtomicPtr::new(results[i].clone()))
    };
}

#[derive(Parser, Debug)]
struct Args {
    #[clap(short, long, parse(from_os_str), value_name = "FILE")]
    config: PathBuf,
    #[clap(short, long, parse(from_os_str), value_name = "FILE", default_value = "websites.jsonl")]
    outfile: PathBuf,
}

fn write_result(key: &str, value: String, core_id: &CoreId) {
    if value.is_empty() { return; }
    let with_proto = format!(",\n[\"{}\", \"{}\"]", key, value);
    let ptr = RESULTS[core_id.raw() as usize].load(Ordering::Relaxed);
    let wtr = unsafe { &mut *ptr};
    wtr.write_all(with_proto.as_bytes()).unwrap();
}

fn dns_cb(dns: &DnsTransaction, core_id: &CoreId) {
    let query_domain = (*dns).query_domain().to_string();
    write_result("dns", query_domain, core_id);
}

fn http_cb(http: &HttpTransaction, core_id: &CoreId) {
    let uri = (*http).uri().to_string();
    write_result("http", uri, core_id);
}

fn tls_cb(tls: &TlsHandshake, core_id: &CoreId) {
    let sni = (*tls).sni().to_string();
    write_result("tls", sni, core_id);
}

fn quic_cb(quic: &QuicStream, core_id: &CoreId) {
    let sni = (*quic).tls.sni().to_string();
    write_result("quic", sni, core_id);
}

fn combine_results(outfile: &PathBuf) {
    let mut result = HashMap::new();
    for core_id in 0..NUM_CORES {
        let ptr = RESULTS[core_id].load(Ordering::Relaxed);
        let wtr = unsafe { &mut *ptr};
        wtr.write_all(b"\n]").unwrap();
        wtr.flush().unwrap();
        let fp = String::from(OUTFILE_PREFIX) + &format!("{}", core_id) + ".jsonl";
        let content = std::fs::read_to_string(fp.clone()).unwrap();
        let values: Vec<(String, String)> = serde_json::from_str(&content).unwrap();
        for res in values {
            if res.0 == "start" { continue; }
            let entry = result.entry(res.0).or_insert_with(HashMap::new);
            *entry.entry(res.1).or_insert(0) += 1;
        }
        std::fs::remove_file(fp).unwrap();
    }
    let file = std::fs::File::create(outfile).unwrap();
    serde_json::to_writer(&file, &result).unwrap();
}

#[subscription("/home/tcr6/retina/examples/websites/spec.toml")]
fn main() {
    let args = Args::parse();
    let config = load_config(&args.config);
    let num_cores = config.get_all_core_ids().len();
    if num_cores > NUM_CORES {
        panic!("Compile-time NUM_CORES ({}) must be <= num cores ({}) in config file", NUM_CORES, num_cores);
    }
    let mut runtime: Runtime<SubscribedWrapper> = Runtime::new(config, filter).unwrap();
    runtime.run();
    combine_results(&args.outfile);
}
