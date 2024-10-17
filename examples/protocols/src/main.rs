use retina_core::config::load_config;
use retina_core::{CoreId, FiveTuple, Runtime};
use retina_datatypes::*;
use retina_filtergen::{filter, retina_main};

use std::fs::File;
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicPtr, Ordering};
use std::sync::OnceLock;

use array_init::array_init;
use clap::Parser;
use serde::{Deserialize, Serialize};

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
        default_value = "protos.jsonl"
    )]
    outfile: PathBuf,
}

// Number of cores being used by the runtime; should match config file
// Should be defined at compile-time so that we can use a
// statically-sized array for RESULTS
const NUM_CORES: usize = 16;
// Add 1 for ARR_LEN to avoid overflow; one core is used as main_core
const ARR_LEN: usize = NUM_CORES + 1;

const OUTFILE_PREFIX: &str = "protos_";
static CORE_FILES: OnceLock<[AtomicPtr<BufWriter<File>>; ARR_LEN]> = OnceLock::new();
fn core_files() -> &'static [AtomicPtr<BufWriter<File>>; ARR_LEN] {
    CORE_FILES.get_or_init(|| {
        let mut outp = vec![];
        for core_id in 0..ARR_LEN {
            let file_name = String::from(OUTFILE_PREFIX) + &format!("{}", core_id) + ".jsonl";
            let core_wtr = BufWriter::new(File::create(&file_name).unwrap());
            let core_wtr = Box::into_raw(Box::new(core_wtr));
            outp.push(core_wtr);
        }
        array_init(|i| AtomicPtr::new(outp[i]))
    })
}

// Ensure OnceLocks are all initialized
fn init() {
    let _ = core_files();
}

#[derive(Serialize, Deserialize, Clone)]
enum ProtoData {
    Dns(DnsData),
    Http(HttpData),
    Tls(TlsData),
    Quic(QuicData),
}

#[derive(Serialize, Deserialize, Clone)]
struct DnsData {
    pub server_subnet: String,
    pub transp_proto: String,
    pub query_domain: String,
}

#[derive(Serialize, Deserialize, Clone)]
struct HttpData {
    pub server_subnet: String,
    pub uri: String,
    pub host: String,
}

#[derive(Serialize, Deserialize, Clone)]
struct TlsData {
    pub server_subnet: String,
    pub sni: String,
}

#[derive(Serialize, Deserialize, Clone)]
struct QuicData {
    pub server_subnet: String,
    pub sni: String,
}

#[filter("dns and ((tcp and tcp.port != 53) or (udp and udp.port != 53))")]
fn dns_cb(dns: &DnsTransaction, five_tuple: &FiveTuple, core_id: &CoreId) {
    let record = ProtoData::Dns(DnsData {
        server_subnet: five_tuple.dst_ip_str(),
        transp_proto: five_tuple.transp_proto_str(),
        query_domain: (*dns).query_domain().to_string(),
    });
    let ptr = core_files()[core_id.raw() as usize].load(Ordering::Relaxed);
    let wtr = unsafe { &mut *ptr };
    if let Ok(s) = serde_json::to_string(&record) {
        writeln!(wtr, "{}", s).unwrap();
    }
}

#[filter("http and tcp and tcp.port != 80 and tcp.port != 8080")]
fn http_cb(http: &HttpTransaction, five_tuple: &FiveTuple, core_id: &CoreId) {
    let txn = ProtoData::Http(HttpData {
        server_subnet: five_tuple.dst_subnet_str(),
        uri: (*http).uri().to_string(),
        host: (*http).host().to_string(),
    });
    let ptr = core_files()[core_id.raw() as usize].load(Ordering::Relaxed);
    let wtr = unsafe { &mut *ptr };
    if let Ok(s) = serde_json::to_string(&txn) {
        writeln!(wtr, "{}", s).unwrap();
    }
}

#[filter("tls and tcp and tcp.port != 443")]
fn tls_cb(tls: &TlsHandshake, five_tuple: &FiveTuple, core_id: &CoreId) {
    let hndshk = ProtoData::Tls(TlsData {
        server_subnet: five_tuple.dst_subnet_str(),
        sni: (*tls).sni().to_string(),
    });
    let ptr = core_files()[core_id.raw() as usize].load(Ordering::Relaxed);
    let wtr = unsafe { &mut *ptr };
    if let Ok(s) = serde_json::to_string(&hndshk) {
        writeln!(wtr, "{}", s).unwrap();
    }
}

#[filter("quic and udp.port != 443")]
fn quic_cb(quic: &QuicStream, five_tuple: &FiveTuple, core_id: &CoreId) {
    let data = ProtoData::Quic(QuicData {
        server_subnet: five_tuple.dst_subnet_str(),
        sni: quic.tls.sni().to_string(),
    });
    let ptr = core_files()[core_id.raw() as usize].load(Ordering::Relaxed);
    let wtr = unsafe { &mut *ptr };
    if let Ok(s) = serde_json::to_string(&data) {
        writeln!(wtr, "{}", s).unwrap();
    }
}

fn combine_results(outfile: &PathBuf) {
    let mut results: Vec<ProtoData> = vec![];
    for core_id in 0..ARR_LEN {
        let ptr = core_files()[core_id].load(Ordering::Relaxed);
        let wtr = unsafe { &mut *ptr };
        wtr.flush().unwrap();
        let fp = String::from(OUTFILE_PREFIX) + &format!("{}", core_id) + ".jsonl";
        let rdr = BufReader::new(File::open(fp.clone()).unwrap());
        let sessions: Vec<ProtoData> = rdr
            .lines()
            .map(|line| serde_json::from_str(&line.unwrap()).unwrap())
            .collect();
        results.extend_from_slice(&sessions);
        std::fs::remove_file(fp).unwrap();
    }
    let mut file = std::fs::File::create(outfile).unwrap();
    let results = serde_json::to_string(&results).unwrap();
    file.write_all(results.as_bytes()).unwrap();
}

#[retina_main(4)]
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
