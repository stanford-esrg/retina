use retina_core::config::load_config;
use retina_core::subscription::{TlsHandshake, TlsHandshakeSubscription};
use retina_core::Runtime;
use retina_filtergen::filter;

use std::cmp;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Mutex;

use anyhow::Result;
use clap::Parser;

#[derive(Parser, Debug)]
struct Args {
    #[clap(short, long, parse(from_os_str), value_name = "FILE")]
    config: PathBuf,
    #[clap(
        short,
        long,
        parse(from_os_str),
        value_name = "FILE",
        default_value = "client_randoms.json"
    )]
    outfile: PathBuf,
}

#[filter("tls")]
fn main() -> Result<()> {
    env_logger::init();
    let args = Args::parse();
    let config = load_config(&args.config);

    // For demonstration purposes, keep everything in memory but provision enough so that it does
    // not re-allocate.
    let client_randoms = Mutex::new(HashMap::with_capacity(100_000_000));

    let callback = |tls: TlsHandshake| {
        let mut randoms = client_randoms.lock().unwrap();
        *randoms.entry(tls.data.client_random()).or_insert(0) += 1;
    };
    let mut runtime: Runtime<TlsHandshakeSubscription> = Runtime::new(config, filter, vec![Box::new(callback)])?;
    runtime.run();

    let randoms = client_randoms.lock().unwrap();
    let mut r = randoms
        .iter()
        .filter(|(k, &v)| v > 1u32 && k.as_str() != "")
        .collect::<Vec<_>>();
    r.sort_by(|a, b| b.1.cmp(a.1));
    // Display most frequently repeated client randoms.
    for (k, v) in r[..cmp::min(10, r.len())].iter() {
        println!("{}: {}", k, v);
    }

    let file = std::fs::File::create(&args.outfile)?;
    serde_json::to_writer(&file, &r)?;
    Ok(())
}
