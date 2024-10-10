use retina_core::config::load_config;
use retina_core::protocols::packet::{ethernet::*, ipv4::*, ipv6::*, tcp::*, udp::*, Packet};
use retina_core::{CoreId, Runtime};
use retina_datatypes::*;
use retina_filtergen::{filter, retina_main};
use retina_core::FiveTuple;

use std::collections::HashMap;
use std::sync::atomic::{AtomicPtr, AtomicUsize, Ordering};
use std::fs::File;
use std::io::{BufWriter, BufReader, Write, BufRead};
use std::sync::OnceLock;
use std::path::PathBuf;

use array_init::array_init;
use clap::Parser;
use serde::{Serialize, Deserialize};

// Number of cores being used by the runtime; should match config file
// Should be defined at compile-time so that we can use a
// statically-sized array for RESULTS
const NUM_CORES: usize = 16;
// Add 1 for ARR_LEN to avoid overflow; one core is used as main_core
const ARR_LEN: usize = NUM_CORES + 1;

static UDP_RESULTS: OnceLock<[AtomicPtr<HashMap<u16, usize>>; ARR_LEN]> = OnceLock::new();
static TCP_RESULTS: OnceLock<[AtomicPtr<HashMap<u16, usize>>; ARR_LEN]> = OnceLock::new();
static UDP_CONN_RESULTS: OnceLock<[AtomicPtr<HashMap<u16, usize>>; ARR_LEN]> = OnceLock::new();
static TCP_CONN_RESULTS: OnceLock<[AtomicPtr<HashMap<u16, usize>>; ARR_LEN]> = OnceLock::new();

fn init_results() -> [AtomicPtr<HashMap<u16, usize>>; ARR_LEN] {
    let mut results = vec![];
    for _ in 0..ARR_LEN {
        results.push(Box::into_raw(Box::new(HashMap::new())));
    }
    array_init(|i| AtomicPtr::new(results[i].clone()))
}

fn udp_results() -> &'static [AtomicPtr<HashMap<u16, usize>>; ARR_LEN] {
    UDP_RESULTS.get_or_init( || {
        init_results()
    })
}

fn tcp_results() -> &'static [AtomicPtr<HashMap<u16, usize>>; ARR_LEN] {
    TCP_RESULTS.get_or_init( || {
        init_results()
    })
}

fn udp_conn_results() -> &'static [AtomicPtr<HashMap<u16, usize>>; ARR_LEN] {
    UDP_CONN_RESULTS.get_or_init( || {
        init_results()
    })
}

fn tcp_conn_results() -> &'static [AtomicPtr<HashMap<u16, usize>>; ARR_LEN] {
    TCP_CONN_RESULTS.get_or_init( || {
        init_results()
    })
}

static UDP_CNT: AtomicUsize = AtomicUsize::new(0);
static TCP_CNT: AtomicUsize = AtomicUsize::new(0);
static UDP_CONN_CNT: AtomicUsize = AtomicUsize::new(0);
static TCP_CONN_CNT: AtomicUsize = AtomicUsize::new(0);

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
        array_init(|i| AtomicPtr::new(outp[i].clone()))
    })
}

fn init() {
    let _ = tcp_results();
    let _ = udp_results();
    let _ = tcp_conn_results();
    let _ = udp_conn_results();
    let _ = core_files();
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
        default_value = "protos.jsonl"
    )]
    outfile: PathBuf,
}

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
    let ptr = udp_results()[core_id.raw() as usize].load(Ordering::Relaxed);
    let dict = unsafe { &mut *ptr };
    *dict.entry(src_port.unwrap()).or_insert(0) += 1;
    *dict.entry(dst_port.unwrap()).or_insert(0) += 1;
    UDP_CNT.fetch_add(1, Ordering::Relaxed);
}

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
    let ptr = tcp_results()[core_id.raw() as usize].load(Ordering::Relaxed);
    let dict = unsafe { &mut *ptr };
    *dict.entry(src_port.unwrap()).or_insert(0) += 1;
    *dict.entry(dst_port.unwrap()).or_insert(0) += 1;
    TCP_CNT.fetch_add(1, Ordering::Relaxed);
}

#[filter("tcp")]
fn tcp_conn_cb(five_tuple: &FiveTuple, core_id: &CoreId) {
    let dst_port = five_tuple.resp.port();
    let src_port = five_tuple.orig.port();
    let ptr = tcp_conn_results()[core_id.raw() as usize].load(Ordering::Relaxed);
    let dict = unsafe { &mut *ptr };
    *dict.entry(src_port).or_insert(0) += 1;
    *dict.entry(dst_port).or_insert(0) += 1;
    TCP_CONN_CNT.fetch_add(1, Ordering::Relaxed);
}

#[filter("udp")]
fn udp_conn_cb(five_tuple: &FiveTuple, core_id: &CoreId) {
    let dst_port = five_tuple.resp.port();
    let src_port = five_tuple.orig.port();
    let ptr = udp_conn_results()[core_id.raw() as usize].load(Ordering::Relaxed);
    let dict = unsafe { &mut *ptr };
    *dict.entry(src_port).or_insert(0) += 1;
    *dict.entry(dst_port).or_insert(0) += 1;
    UDP_CONN_CNT.fetch_add(1, Ordering::Relaxed);
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
    pub server_ip: String,
    pub transp_proto: String,
    pub query_domain: String,
}

// Look for DNS connections on unusual ports
#[filter("dns and ((tcp and tcp.port != 53 and tcp.port != 853) or (udp and udp.port != 53 and udp.port != 853))")]
fn dns_cb(dns: &DnsTransaction, five_tuple: &FiveTuple, core_id: &CoreId) {
    let record = ProtoData::Dns(DnsData {
        server_ip: five_tuple.dst_ip_str(),
        transp_proto: five_tuple.transp_proto_str(),
        query_domain: (*dns).query_domain().to_string(),
    });

    let ptr = core_files()[core_id.raw() as usize].load(Ordering::Relaxed);
    let wtr = unsafe { &mut *ptr };
    if let Ok(s) = serde_json::to_string(&record) {
        writeln!(wtr, "{}", s).unwrap();
    }
}

#[derive(Serialize, Deserialize, Clone)]
struct HttpData {
    pub server_subnet: String,
    pub transp_proto: String,
    pub uri: String,
    pub host: String,
    pub status_code: String,
}
// Look for HTTP connections on unusual ports
#[filter("http and tcp and tcp.port != 80 and tcp.port != 8080")]
fn http_cb(http: &HttpTransaction, five_tuple: &FiveTuple, core_id: &CoreId) {
    let txn = ProtoData::Http(HttpData {
        server_subnet: five_tuple.dst_subnet_str(),
        transp_proto: five_tuple.transp_proto_str(),
        uri: (*http).uri().to_string(),
        host: (*http).host().to_string(),
        status_code: (*http).status_code().to_string(),
    });
    let ptr = core_files()[core_id.raw() as usize].load(Ordering::Relaxed);
    let wtr = unsafe { &mut *ptr };
    if let Ok(s) = serde_json::to_string(&txn) {
        writeln!(wtr, "{}", s).unwrap();
    }
}

#[derive(Serialize, Deserialize, Clone)]
struct TlsData {
    pub server_ip_subnet: String,
    pub transp_proto: String,
    pub sni: String,
    pub server_cipher: String,
    pub extensions: String,
}

// Look for TLS connections on unusual ports
#[filter("tls and tcp and tcp.port != 443")]
fn tls_cb(tls: &TlsHandshake, five_tuple: &FiveTuple, core_id: &CoreId) {
    let hndshk = ProtoData::Tls(TlsData {
        server_ip_subnet: five_tuple.dst_subnet_str(),
        transp_proto: five_tuple.transp_proto_str(),
        sni: (*tls).sni().to_string(),
        server_cipher: (*tls).cipher().to_string(),
        extensions: (*tls).server_extensions().join(", "),
    });
    let ptr = core_files()[core_id.raw() as usize].load(Ordering::Relaxed);
    let wtr = unsafe { &mut *ptr };
    if let Ok(s) = serde_json::to_string(&hndshk) {
        writeln!(wtr, "{}", s).unwrap();
    }
}

#[derive(Serialize, Deserialize, Clone)]
struct QuicData {
    pub server_subnet: String,
    pub transp_proto: String,
    pub sni: String,
}

// Look for QUIC connections on unusual ports
#[filter("quic")]
fn quic_cb(quic: &QuicStream, five_tuple: &FiveTuple, core_id: &CoreId) {
    let data = ProtoData::Quic(QuicData {
        server_subnet: five_tuple.dst_subnet_str(),
        transp_proto: five_tuple.transp_proto_str(),
        sni: (*quic).tls.sni().to_string(),
    });
    let ptr = core_files()[core_id.raw() as usize].load(Ordering::Relaxed);
    let wtr = unsafe { &mut *ptr };
    if let Ok(s) = serde_json::to_string(&data) {
        writeln!(wtr, "{}", s).unwrap();
    }
}

#[derive(Serialize, Default)]
struct Results {
    pub udp_pkts: HashMap<u16, usize>,
    pub tcp_pkts: HashMap<u16, usize>,
    pub udp_conns: HashMap<u16, usize>,
    pub tcp_conns: HashMap<u16, usize>,
    pub sessions: Vec<ProtoData>,
}

fn combine_results(outfile: &PathBuf) {
    let mut results = Results::default();
    for core_id in 0..ARR_LEN {
        // TCP per-port packet counts
        let ptr = tcp_results()[core_id as usize].load(Ordering::SeqCst);
        let dict = unsafe { &*ptr };
        results.tcp_pkts.extend(dict);

        // TCP per-port conn counts
        let ptr = tcp_conn_results()[core_id as usize].load(Ordering::SeqCst);
        let dict = unsafe { &*ptr };
        results.tcp_conns.extend(dict);

        // UDP per-port packet counts
        let ptr = udp_results()[core_id as usize].load(Ordering::SeqCst);
        let dict = unsafe { &*ptr };
        results.udp_pkts.extend(dict);

        // UDP per-port conn counts
        let ptr = udp_conn_results()[core_id as usize].load(Ordering::SeqCst);
        let dict = unsafe { &*ptr };
        results.udp_conns.extend(dict);

        // Sessions on unexpected ports
        let ptr = core_files()[core_id as usize].load(Ordering::Relaxed);
        let wtr = unsafe { &mut *ptr };
        wtr.flush().unwrap();
        let fp = String::from(OUTFILE_PREFIX) + &format!("{}", core_id) + ".jsonl";
        let rdr = BufReader::new(File::open(fp.clone()).unwrap());
        let sessions: Vec<ProtoData> = rdr.lines()
                                            .into_iter()
                                            .map(|line| {
                                                serde_json::from_str(
                                                    &line.unwrap()
                                                ).unwrap()
                                            }).collect();
        results.sessions.extend_from_slice(&sessions);
        std::fs::remove_file(fp).unwrap();
    }
    let mut file = std::fs::File::create(outfile).unwrap();
    let results = serde_json::to_string(&results).unwrap();
    file.write_all(results.as_bytes()).unwrap();
}

#[retina_main(8)]
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
        "Got {} tcp, {} udp packets",
        TCP_CNT.load(Ordering::SeqCst),
        UDP_CNT.load(Ordering::SeqCst)
    );
}
