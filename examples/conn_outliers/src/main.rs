use retina_core::config::load_config;
use retina_core::{CoreId, Runtime, FiveTuple};
use retina_datatypes::*;
use retina_filtergen::{filter, retina_main};
use retina_core::protocols::stream::SessionData;

use std::io::Write;
use std::sync::atomic::{Ordering, AtomicPtr};
use std::time::Duration;
use std::net::SocketAddr::{V4, V6};

use array_init::array_init;
use clap::Parser;
use lazy_static::lazy_static;
use std::path::PathBuf;

// Number of cores being used by the runtime; should match config file
// Should be defined at compile-time so that we can use a
// statically-sized array for RESULTS
const NUM_CORES: usize = 16;
// Add 1 for ARR_LEN to avoid overflow; one core is used as main_core
const ARR_LEN: usize = NUM_CORES + 1;

fn init_results() -> [AtomicPtr<Vec<RawConnStats>>; ARR_LEN] {
    array_init(|_| AtomicPtr::new(Box::into_raw(Box::new(Vec::new()))))
}

lazy_static! {
    static ref RESULTS: [AtomicPtr<Vec<RawConnStats>>; ARR_LEN] = init_results();
}

enum Proto {
    Http,
    Quic,
    Dns,
    Tls,
    Tcp,
    Udp,
    Ipv4,
    Ipv6,
    None
}

impl Proto {
    pub(crate) fn from_sessions(sessions: &SessionList,
                                five_tuple: &FiveTuple) -> Vec<Proto> {
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

struct RawConnStats {
    five_tuple: FiveTuple,
    eth: EthAddr,
    history: ConnHistory,
    interarrivals: InterArrivals,
    byte_count: usize,
    pkt_count: usize,
    duration: Duration,
    protos: Vec<Proto>
}

struct ConnStats {
    src_port: u16,
    dst_port: u16,
    iot: Option<String>,
    history: ConnHistory,
    interarrivals: InterArrivals,
    byte_count: usize,
    pkt_count: usize,
    duration_ms: u128,
    protos: Vec<Proto>
}

impl ConnStats {
    fn from_raw(stats: &mut RawConnStats) -> Self {
        let mut src_port = 0;
        let mut dst_port = 0;

        // Populate protocols with TCP/UDP layer
        let mut protos = std::mem::take(&mut stats.protos);
        if matches!(stats.five_tuple.proto, TCP_PROTOCOL) {
            protos.push(Proto::Tcp);
        } else if matches!(stats.five_tuple.proto, UDP_PROTOCOL) {
            protos.push(Proto::Udp);
        }

        // Populate protocols with IP layer
        // Populate src/dst ports
        if let V4(src) = stats.five_tuple.orig {
            protos.push(Proto::Ipv4);
            src_port = src.port();
            if let V4(dst) = stats.five_tuple.resp {
                dst_port = dst.port();
            }
        } else if let V6(src) = stats.five_tuple.orig {
            protos.push(Proto::Ipv6);
            src_port = src.port();
            if let V6(dst) = stats.five_tuple.resp {
                dst_port = dst.port();
            }
        }
        // Don't write raw MAC addresses to disk
        // Just check for known IoT devices
        // TODO
        // let iot = lookup_iot(&stats.eth.src, &stats.eth.dst);

        Self {
            src_port,
            dst_port,
            iot: None,
            history: std::mem::take(&mut stats.history),
            interarrivals: stats.interarrivals.clone(),
            byte_count: stats.byte_count,
            pkt_count: stats.pkt_count,
            duration_ms: stats.duration.as_millis(),
            protos,
        }
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

const LOW_DURATION_THRESH_MS: u128 = 100;
const HIGH_DURATION_THRESH_MS: u128 = 1_000 * 60 * 5; // 5 mins
const PKT_CNT_LOW_THRESH: usize = 2;


fn save_record(stats: RawConnStats, core_id: &CoreId) {
    let ptr = RESULTS[core_id.raw() as usize].load(Ordering::Relaxed);
    let v = unsafe { &mut *ptr };
    v.push(stats);
}

#[allow(clippy::too_many_arguments)]
#[filter("")]
fn record(core_id: &CoreId, history: &ConnHistory, interarrivals: &InterArrivals,
          byte_count: &ByteCount, pkt_count: &PktCount, duration: &ConnDuration,
          sessions: &SessionList, five_tuple: &FiveTuple, ethaddr: &EthAddr) {

    if duration.duration_ms() < LOW_DURATION_THRESH_MS ||
       duration.duration_ms() > HIGH_DURATION_THRESH_MS ||
       pkt_count.pkt_count < PKT_CNT_LOW_THRESH {
        save_record(
            RawConnStats {
                five_tuple: *five_tuple,
                eth: ethaddr.clone(),
                history: history.clone(),
                interarrivals: interarrivals.clone(),
                byte_count: byte_count.byte_count,
                pkt_count: pkt_count.pkt_count,
                duration: duration.duration(),
                protos: Proto::from_sessions(sessions, five_tuple),
            },
            core_id
        );
    }
}

fn process_results(outfile: &PathBuf) {

}

#[retina_main(1)]
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
    process_results(&args.outfile);
}
