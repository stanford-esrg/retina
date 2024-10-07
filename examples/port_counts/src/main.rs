use retina_core::config::load_config;
use retina_core::protocols::packet::{ethernet::*, ipv4::*, ipv6::*, tcp::*, udp::*, Packet};
use retina_core::{CoreId, Runtime};
use retina_datatypes::*;
use retina_filtergen::{filter, retina_main};

use std::collections::HashMap;
use std::io::Write;
use std::sync::atomic::{AtomicPtr, AtomicUsize, Ordering};

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

fn init_results() -> [AtomicPtr<HashMap<u16, usize>>; ARR_LEN] {
    let mut results = vec![];
    for _ in 0..ARR_LEN {
        results.push(Box::into_raw(Box::new(HashMap::new())));
    }
    array_init(|i| AtomicPtr::new(results[i].clone()))
}

lazy_static! {
    static ref UDP_RESULTS: [AtomicPtr<HashMap<u16, usize>>; ARR_LEN] = init_results();
    static ref TCP_RESULTS: [AtomicPtr<HashMap<u16, usize>>; ARR_LEN] = init_results();
    static ref WLAN_CNT: AtomicUsize = AtomicUsize::new(0);
    static ref ETH_CNT: AtomicUsize = AtomicUsize::new(0);
    static ref UDP_CNT: AtomicUsize = AtomicUsize::new(0);
    static ref TCP_CNT: AtomicUsize = AtomicUsize::new(0);
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
    let ptr = UDP_RESULTS[core_id.raw() as usize].load(Ordering::Relaxed);
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
    let ptr = TCP_RESULTS[core_id.raw() as usize].load(Ordering::Relaxed);
    let dict = unsafe { &mut *ptr };
    *dict.entry(src_port.unwrap()).or_insert(0) += 1;
    *dict.entry(dst_port.unwrap()).or_insert(0) += 1;
    TCP_CNT.fetch_add(1, Ordering::Relaxed);
}

#[filter("udp and udp.port = 5247")] // capwap
fn wlan_l2t_cb(_mbuf: &ZcFrame) {
    WLAN_CNT.fetch_add(1, Ordering::Relaxed);
}

/*
#[filter("")] // all
fn eth_cb(_mbuf: &ZcFrame) {
    ETH_CNT.fetch_add(1, Ordering::Relaxed);
}
 */

fn combine_results(outfile: &PathBuf) {
    let mut results = HashMap::from([("udp", HashMap::new()), ("tcp", HashMap::new())]);
    for core_id in 0..ARR_LEN {
        let ptr = TCP_RESULTS[core_id as usize].load(Ordering::SeqCst);
        let dict = unsafe { &mut *ptr };
        results.get_mut("tcp").unwrap().extend(dict);

        let ptr = UDP_RESULTS[core_id as usize].load(Ordering::SeqCst);
        let dict = unsafe { &mut *ptr };
        results.get_mut("udp").unwrap().extend(dict);
    }
    let mut file = std::fs::File::create(outfile).unwrap();
    let results = serde_json::to_string(&results).unwrap();
    file.write_all(results.as_bytes()).unwrap();
}

#[retina_main(3)]
fn main() {
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
        "Got {} wlan, {} tcp, {} udp packets",
        WLAN_CNT.load(Ordering::SeqCst),
        TCP_CNT.load(Ordering::SeqCst),
        UDP_CNT.load(Ordering::SeqCst)
    );
}
