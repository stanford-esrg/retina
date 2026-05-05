use retina_core::config::load_config;
use retina_core::rte_rdtsc;
use retina_core::subscription::*;
use retina_core::Runtime;
use retina_filtergen::filter;

use anyhow::Result;
use clap::Parser;
use std::path::PathBuf;

#[derive(Parser, Debug)]
struct Args {
    #[clap(short, long, parse(from_os_str), value_name = "FILE")]
    config: PathBuf,
    #[clap(short, long)]
    spin: u64,
}

#[filter("tls")]
fn main() -> Result<()> {
    env_logger::init();
    let args = Args::parse();
    let config = load_config(&args.config);

    let cycles = args.spin;
    let callback = |_: TlsHandshake| {
        spin(cycles);
    };
    let mut runtime = Runtime::new(config, filter, callback)?;
    runtime.run();
    Ok(())
}

#[inline]
fn spin(cycles: u64) {
    if cycles == 0 {
        return;
    }
    let start = unsafe { rte_rdtsc() };
    loop {
        let now = unsafe { rte_rdtsc() };
        if now - start > cycles {
            break;
        }
    }
}
