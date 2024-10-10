use retina_core::config::load_config;
use retina_core::protocols::packet::{tcp::TCP_PROTOCOL, udp::UDP_PROTOCOL};
use retina_core::protocols::stream::SessionData;
use retina_core::{CoreId, FiveTuple, Runtime};
use retina_datatypes::*;
use retina_filtergen::{filter, retina_main};
use std::net::{Ipv4Addr, Ipv6Addr};

use std::fs::File;
use std::io::{BufWriter, Write};
use std::net::SocketAddr::{V4, V6};
use std::path::PathBuf;
use std::sync::atomic::{AtomicPtr, Ordering};
use std::sync::OnceLock;

use array_init::array_init;
use clap::Parser;
use serde::Serialize;

// Number of cores being used by the runtime; should match config file
// Should be defined at compile-time so that we can use a
// statically-sized array for RESULTS
const NUM_CORES: usize = 16;
// Add 1 for ARR_LEN to avoid overflow; core 0 is typically used as main_core
const ARR_LEN: usize = NUM_CORES + 1;
// Temp per-core files
const OUTFILE_PREFIX: &str = "conns_";

static RESULTS: OnceLock<[AtomicPtr<BufWriter<File>>; ARR_LEN]> = OnceLock::new();

fn results() -> &'static [AtomicPtr<BufWriter<File>>; ARR_LEN] {
    RESULTS.get_or_init(|| {
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

fn init() {
    let _ = results();
}

#[derive(Debug, Serialize)]
enum Proto {
    Http,
    Quic,
    Dns,
    Tls,
    Tcp,
    Udp,
    Ipv4,
    Ipv6,
}

impl Proto {
    pub(crate) fn from_sessions(sessions: &SessionList) -> Vec<Proto> {
        let mut ret = Vec::with_capacity(sessions.len());

        for session in sessions {
            if matches!(session.data, SessionData::Tls(_)) {
                ret.push(Proto::Tls);
            } else if matches!(session.data, SessionData::Dns(_)) {
                ret.push(Proto::Dns);
            } else if matches!(session.data, SessionData::Http(_)) {
                ret.push(Proto::Http);
            } else if matches!(session.data, SessionData::Quic(_)) {
                ret.push(Proto::Quic);
            }
        }
        ret
    }
}

#[derive(Serialize)]
struct ConnStats {
    server_v4: Option<Ipv4Addr>,
    server_v6: Option<Ipv6Addr>,
    client_private: bool,
    src_port: u16,
    dst_port: u16,
    history: ConnHistory,
    interarrivals: InterArrivals,
    byte_count: usize,
    pkt_count: usize,
    duration_ms: u128,
    protos: Vec<Proto>,
}

impl ConnStats {
    fn new() -> Self {
        Self {
            server_v4: None,
            server_v6: None,
            client_private: false,
            src_port: 0,
            dst_port: 0,
            history: ConnHistory { history: vec![] },
            interarrivals: InterArrivals::new_empty(),
            byte_count: 0,
            pkt_count: 0,
            duration_ms: 0,
            protos: vec![],
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn from_raw(
        history: &ConnHistory,
        interarrivals: &InterArrivals,
        byte_count: &ByteCount,
        pkt_count: &PktCount,
        duration: &ConnDuration,
        sessions: &SessionList,
        five_tuple: &FiveTuple,
    ) -> Self {
        let mut output = ConnStats::new();

        // Populate protocols with TCP/UDP layer
        output.protos = Proto::from_sessions(sessions);
        if matches!(five_tuple.proto, TCP_PROTOCOL) {
            output.protos.push(Proto::Tcp);
        } else if matches!(five_tuple.proto, UDP_PROTOCOL) {
            output.protos.push(Proto::Udp);
        }

        // Populate protocols with IP layer
        // Populate src/dst ports
        if let V4(src) = five_tuple.orig {
            output.protos.push(Proto::Ipv4);
            output.src_port = src.port();
            if let V4(dst) = five_tuple.resp {
                output.dst_port = dst.port();
                if dst.ip().is_broadcast() || dst.ip().is_multicast() {
                    output.server_v4 = Some(*dst.ip());
                } else {
                    let mask = !0u32 << (32 - 24); // Convert to a /24
                    output.server_v4 = Some(Ipv4Addr::from(dst.ip().to_bits() & mask));
                }
            }
            output.client_private = src.ip().is_private();
        } else if let V6(src) = five_tuple.orig {
            output.protos.push(Proto::Ipv6);
            output.src_port = src.port();
            if let V6(dst) = five_tuple.resp {
                output.dst_port = dst.port();
                let mask = !0u128 << (128 - 64); // Convert to a /64
                output.server_v6 = Some(Ipv6Addr::from(dst.ip().to_bits() & mask));
            }
        }
        output.history = history.clone();
        output.byte_count = byte_count.raw();
        output.pkt_count = pkt_count.raw();
        output.duration_ms = duration.duration().as_millis();
        output.interarrivals = interarrivals.clone();

        output
    }
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
        default_value = "outliers.jsonl"
    )]
    outfile: PathBuf,
}

const HIGH_DURATION_THRESH_MS: u128 = 1_000 * 60 * 5; // 5 mins
const LOW_PKT_THRESH: usize = 50; // Low packets

fn save_record(stats: ConnStats, core_id: &CoreId) {
    let ptr = results()[core_id.raw() as usize].load(Ordering::Relaxed);
    let wtr = unsafe { &mut *ptr };
    let outp = serde_json::to_string(&stats).unwrap();
    wtr.write_all(outp.as_bytes()).unwrap();
}

// Ignore Zoom
#[allow(clippy::too_many_arguments)]
#[filter("(tcp and tcp.port != 8801 and tcp.port != 8802) or (udp and udp.port < 8801 and udp.port > 8810)")]
fn record(
    core_id: &CoreId,
    history: &ConnHistory,
    interarrivals: &InterArrivals,
    byte_count: &ByteCount,
    pkt_count: &PktCount,
    duration: &ConnDuration,
    sessions: &SessionList,
    five_tuple: &FiveTuple,
) {
    // Look for connections that send few packets over high amt of time
    if duration.duration_ms() > HIGH_DURATION_THRESH_MS && pkt_count.pkt_count < LOW_PKT_THRESH {
        save_record(
            ConnStats::from_raw(
                history,
                interarrivals,
                byte_count,
                pkt_count,
                duration,
                sessions,
                five_tuple,
            ),
            core_id,
        );
    }
}

fn process_results(outfile: &PathBuf) {
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

#[retina_main(1)]
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
    process_results(&args.outfile);
}
