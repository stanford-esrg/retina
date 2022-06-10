use retina_core::config::load_config;
use retina_core::subscription::Connection;
use retina_core::Runtime;
use retina_filtergen::filter;

use std::collections::BinaryHeap;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use anyhow::Result;
use clap::Parser;
use csv::Writer;
use hashlink::linked_hash_map::RawEntryMut;
use hashlink::LinkedHashMap;

#[derive(Parser, Debug)]
struct Args {
    #[clap(short, long, parse(from_os_str), value_name = "FILE")]
    config: PathBuf,
    #[clap(
        short,
        long,
        parse(from_os_str),
        value_name = "FILE",
        default_value = "video.csv"
    )]
    outfile: PathBuf,
}

#[filter("tls.sni ~ '(.+?\\.)?nflxvideo\\.net'")]
fn main() -> Result<()> {
    env_logger::init();
    let args = Args::parse();
    let config = load_config(&args.config);

    // For demonstration purposes, keep everything in memory but provision enough so that it does
    // not re-allocate.
    let sessions = Mutex::new(LinkedHashMap::with_capacity(100_000_000));
    let mut wtr = Writer::from_path(&args.outfile)?;
    wtr.write_record(&[
        "client",
        "parallel_flows",
        "bytes_up",
        "bytes_dn",
        "avg_ooo_up",
        "avg_ooo_dn",
        "tot_tput_dn",
        "duration",
    ])?;
    let wtr = Mutex::new(wtr);

    let callback = |conn: Connection| {
        let client = conn.five_tuple.orig.ip();
        // maps clients to video sessions
        let mut sessions = sessions.lock().unwrap();
        let now = Instant::now();
        match (*sessions).raw_entry_mut().from_key(&client) {
            RawEntryMut::Occupied(mut occupied) => {
                occupied.to_back();
                let session: &mut Session = occupied.get_mut();
                session.last_updated = now;
                session.connections.push(conn);
            }
            RawEntryMut::Vacant(vacant) => {
                vacant.insert(client, Session::new(now, conn));
            }
        }
        if let Some((client, session)) = sessions.front() {
            if now.duration_since(session.last_updated) > Duration::from_millis(500) {
                let conns = &session.connections;
                let intervals = conns
                    .iter()
                    .map(|c| (c.ts, c.ts + c.duration))
                    .collect::<Vec<_>>();
                let parallel_flows = max_overlap(intervals);
                let mut bytes_up = 0;
                let mut bytes_dn = 0;
                let mut ooo_pkts_up = 0.0;
                let mut ooo_pkts_dn = 0.0;
                let mut tput_dn = 0.0;
                for c in conns {
                    bytes_up += c.orig.nb_bytes;
                    bytes_dn += c.resp.nb_bytes;
                    ooo_pkts_up += c.orig.gaps.len() as f64;
                    ooo_pkts_dn += c.resp.gaps.len() as f64;
                    tput_dn += 8.0 * c.resp.nb_bytes as f64 / c.duration.as_micros() as f64;
                }
                let last = conns[conns.len() - 1].ts + conns[conns.len() - 1].duration;
                let duration = last.saturating_duration_since(conns[0].ts);

                let mut wtr = wtr.lock().unwrap();
                wtr.serialize((
                    client,
                    parallel_flows,
                    bytes_up,
                    bytes_dn,
                    ooo_pkts_up / conns.len() as f64,
                    ooo_pkts_dn / conns.len() as f64,
                    tput_dn / conns.len() as f64 * parallel_flows as f64,
                    duration.as_millis(),
                ))
                .unwrap();
                sessions.pop_front();
            }
        }
    };
    let mut runtime = Runtime::new(config, filter, callback)?;
    runtime.run();

    wtr.lock().unwrap().flush()?;
    Ok(())
}

/// A video session that contains multiple network flows.
#[derive(Debug)]
struct Session {
    last_updated: Instant,
    connections: Vec<Connection>,
}

impl Session {
    fn new(now: Instant, conn: Connection) -> Self {
        Session {
            last_updated: now,
            connections: vec![conn],
        }
    }
}

fn max_overlap(mut intervals: Vec<(Instant, Instant)>) -> usize {
    let mut ends = BinaryHeap::new();
    intervals.sort_by_key(|k| k.0);
    for (start, end) in intervals.iter() {
        if let Some(t) = ends.peek() {
            if start > t {
                ends.pop();
            }
        }
        ends.push(*end);
    }
    ends.len()
}
