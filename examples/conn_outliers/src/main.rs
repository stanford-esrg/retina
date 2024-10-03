use retina_core::config::load_config;
use retina_core::{CoreId, Runtime, FiveTuple};
use retina_datatypes::*;
use retina_filtergen::{filter, retina_main};
use retina_core::protocols::stream::SessionData;

use std::io::Write;
use std::sync::atomic::{Ordering, AtomicPtr};
use std::time::Duration;

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

fn init_results() -> [AtomicPtr<Vec<ConnStats>>; ARR_LEN] {
    array_init(|_| AtomicPtr::new(Box::into_raw(Box::new(Vec::new()))))
}

lazy_static! {
    static ref RESULTS: [AtomicPtr<Vec<ConnStats>>; ARR_LEN] = init_results();
}

enum Proto {
    Http,
    Quic,
    Dns,
    Tls,
    None
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

struct ConnStats {
    five_tuple: FiveTuple,
    eth: EthAddr,
    history: ConnHistory,
    interarrivals: InterArrivals,
    byte_count: usize,
    pkt_count: usize,
    duration: Duration,
    protos: Vec<Proto>
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


fn save_record(stats: ConnStats, core_id: &CoreId) {
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
            ConnStats {
                five_tuple: *five_tuple,
                eth: ethaddr.clone(),
                history: history.clone(),
                interarrivals: interarrivals.clone(),
                byte_count: byte_count.byte_count,
                pkt_count: pkt_count.pkt_count,
                duration: duration.duration(),
                protos: Proto::from_sessions(sessions),
            },
            core_id
        );
    }
}

fn combine_results(outfile: &PathBuf) {
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
    combine_results(&args.outfile);
}
