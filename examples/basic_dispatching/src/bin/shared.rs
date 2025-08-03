use retina_core::multicore::{ChannelDispatcher, ChannelMode, SharedWorkerThreadSpawner};
use retina_core::{config::load_config, CoreId, Runtime};
use retina_datatypes::{ConnRecord, DnsTransaction, TlsHandshake};
use retina_filtergen::{filter, retina_main};
use std::sync::{Arc, OnceLock};
use std::path::PathBuf;
use clap::Parser;

static TLS_DISPATCHER: OnceLock<Arc<ChannelDispatcher<Event>>> = OnceLock::new();
static DNS_DISPATCHER: OnceLock<Arc<ChannelDispatcher<Event>>> = OnceLock::new();

#[derive(Copy, Clone, Debug, clap::ValueEnum)]
enum ChannelModeArg {
    PerCore,
    Shared,
}

#[derive(Parser, Debug)]
struct Args {
    #[clap(short, long, parse(from_os_str), value_name = "FILE", default_value = "./configs/offline.toml")]
    config: PathBuf,
    
    #[clap(long, value_name = "SIZE", default_value = "1024")]
    tls_channel_size: usize,
    
    #[clap(long, value_name = "SIZE", default_value = "1024")]
    dns_channel_size: usize,

    #[clap(long, value_delimiter = ',', value_name = "TLS_CORES", default_value = "36,37,38,39")]
    worker_cores: Vec<u32>,

    #[clap(long, value_name = "SIZE", default_value = "1")]
    batch_size: usize,

    #[clap(long, value_enum, default_value = "per-core")]
    channel_mode: ChannelModeArg,
}

#[derive(Clone)]
enum Event {
    Tls((TlsHandshake, ConnRecord)),
    Dns((DnsTransaction, ConnRecord)),
}

#[filter("tls")]
fn tls_cb(tls: &TlsHandshake, conn_record: &ConnRecord, rx_core: &CoreId) {
    if let Some(dispatcher) = TLS_DISPATCHER.get() {
        let _ = dispatcher.dispatch(
            Event::Tls((tls.clone(), conn_record.clone())),
            Some(rx_core),
        );
    }
}

#[filter("dns")]
fn dns_cb(dns: &DnsTransaction, conn_record: &ConnRecord, rx_core: &CoreId) {
    if let Some(dispatcher) = DNS_DISPATCHER.get() {
        let _ = dispatcher.dispatch(
            Event::Dns((dns.clone(), conn_record.clone())),
            Some(rx_core),
        );
    }
}

#[retina_main(2)]
fn main() {
    let args = Args::parse();
    println!("{:#?}", args);

    let config = load_config(&args.config);
    let rx_cores = config.get_all_rx_core_ids();

    let channel_mode = match args.channel_mode {
        ChannelModeArg::PerCore => ChannelMode::PerCore(rx_cores),
        ChannelModeArg::Shared => ChannelMode::Shared,
    };

    let tls_dispatcher = Arc::new(ChannelDispatcher::new(
        channel_mode.clone(),
        args.tls_channel_size,
    ));

    let dns_dispatcher = Arc::new(ChannelDispatcher::new(
        channel_mode.clone(),
        args.dns_channel_size,
    ));

    TLS_DISPATCHER
        .set(tls_dispatcher.clone())
        .map_err(|_| "Failed to set TLS dispatcher")
        .unwrap();
    DNS_DISPATCHER
        .set(dns_dispatcher.clone())
        .map_err(|_| "Failed to set DNS dispatcher")
        .unwrap();

    let core_ids: Vec<CoreId> = args.worker_cores
        .iter()
        .map(|&core| CoreId(core))
        .collect();
    
    let worker_handle = SharedWorkerThreadSpawner::new()
        .set_cores(core_ids)
        .set_batch_size(args.batch_size)
        .add_dispatcher(tls_dispatcher.clone(), |event: Event| {
            if let Event::Tls((_tls, _conn_record)) = event {
                // add handler here
            }
        })
        .add_dispatcher(dns_dispatcher.clone(), |event: Event| {
            if let Event::Dns((_dns, _conn_record)) = event {
                // add handler here 
            }
        })
        .run();

    let mut runtime: Runtime<SubscribedWrapper> = Runtime::new(config, filter).unwrap();
    runtime.run();
    
    let final_stats = worker_handle.shutdown();
    
    if let Some(tls_stats) = final_stats.get(0) {
        println!("=== TLS Stats ===\n{}\n", tls_stats);
    }
    
    if let Some(dns_stats) = final_stats.get(1) {
        println!("=== DNS Stats ===\n{}", dns_stats);
    }
}