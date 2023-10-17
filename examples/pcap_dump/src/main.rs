use retina_core::config::default_config;
use retina_core::subscription::Frame;
use retina_core::Runtime;
use retina_filtergen::filter;

use std::fs::File;
use std::path::PathBuf;
use std::sync::Mutex;

use anyhow::Result;
use clap::Parser;
use pcap_file::pcap::PcapWriter;

#[derive(Parser, Debug)]
struct Args {
    // #[clap(short, long, parse(from_os_str), value_name = "FILE")]
    // config: PathBuf,
    #[clap(
        short,
        long,
        parse(from_os_str),
        value_name = "FILE",
        default_value = "dump.pcap"
    )]
    outfile: PathBuf,
}

#[filter("ipv4.total_length in 128..256 and ipv4.src_addr in 192.0.0.0/8")]
fn main() -> Result<()> {
    env_logger::init();
    let args = Args::parse();
    let config = default_config();

    // let file = File::create(&args.outfile)?;
    // let pcap_writer = Mutex::new(PcapWriter::new(file)?);

    let callback = |pkt: Frame| {
        println!("{:?}", pkt);
        /*
        let mut pcap_writer = pcap_writer.lock().unwrap();
        pcap_writer
            .write(1, 0, &pkt.data, pkt.data.len() as u32)
            .unwrap();
         */
    };
    let mut runtime: Runtime<Frame> = Runtime::new(config, filter, vec![Box::new(callback)])?;
    runtime.run();
    Ok(())
}
