use clap::Parser;
use lazy_static::lazy_static;
use retina_core::{config::load_config, FiveTuple, Runtime};
use retina_datatypes::{ByteCount, TlsHandshake};
use retina_filtergen::{filter, retina_main};
use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

// Count how many times the TLS callback is invoked
static TLS_CB_COUNT: AtomicUsize = AtomicUsize::new(0);

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

#[derive(Debug, serde::Serialize)]
struct TlsResult {
    sni: Option<String>,
    five_tuple: FiveTuple,
    byte_count: usize,
}

lazy_static! {
    static ref RESULTS: Mutex<Vec<TlsResult>> = Mutex::new(Vec::new());
}

#[filter("tls")]
fn tls_cb(tls: &TlsHandshake, bytecount: &ByteCount, five_tuple: &FiveTuple) {
    TLS_CB_COUNT.fetch_add(1, Ordering::Relaxed);

    let result = TlsResult {
        sni: Some(tls.sni().to_string()),
        five_tuple: five_tuple.clone(),
        byte_count: bytecount.byte_count,
    };

    {
        let mut vec = RESULTS.lock().unwrap();
        vec.push(result);
    }
}

#[retina_main(1)]
fn main() {
    let args = Args::parse();
    let config = load_config(&args.config);
    let mut runtime: Runtime<SubscribedWrapper> = Runtime::new(config, filter).unwrap();
    runtime.run();

    // Print results to stdout as pretty JSON
    if let Ok(results) = RESULTS.lock() {
        let json = serde_json::to_string_pretty(&*results).unwrap();
        println!("{}", json);
        let mut file = std::fs::File::create(&args.outfile).unwrap();
        file.write_all(json.as_bytes()).unwrap();
    }
    println!("TLS Callback Count: {:?}", TLS_CB_COUNT);
}
