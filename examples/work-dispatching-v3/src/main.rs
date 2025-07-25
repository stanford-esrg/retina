use retina_core::multicore::{ChannelDispatcher, ChannelMode, DedicatedWorkerThreadSpawner};
use retina_core::{config::load_config, CoreId, Runtime};
use retina_datatypes::{ConnRecord, DnsTransaction, TlsHandshake};
use retina_filtergen::{filter, retina_main};
use std::sync::{Arc, OnceLock};
use std::path::PathBuf;
use clap::Parser;

static TLS_DISPATCHER: OnceLock<Arc<ChannelDispatcher<Event>>> = OnceLock::new();
static DNS_DISPATCHER: OnceLock<Arc<ChannelDispatcher<Event>>> = OnceLock::new();

// Argument parsing
#[derive(Parser, Debug)]
struct Args {
    #[clap(short, long, parse(from_os_str), value_name = "FILE", default_value = "./configs/offline.toml")]
    config: PathBuf,
    
    #[clap(long, value_name = "SIZE", default_value = "1024")]
    tls_channel_size: usize,
    
    #[clap(long, value_name = "SIZE", default_value = "1024")]
    dns_channel_size: usize,

    #[clap(long, value_delimiter = ',', value_name = "TLS_CORES", default_value = "36,37")]
    tls_worker_cores: Vec<u32>,

    #[clap(long, value_delimiter = ',', value_name = "DNS_CORES", default_value = "38,39")]
    dns_worker_cores: Vec<u32>,
}

#[derive(Clone)]
enum Event {
    Tls((TlsHandshake, ConnRecord)),
    Dns((DnsTransaction, ConnRecord)),
}

#[filter("tls")]
fn tls_cb(tls: &TlsHandshake, conn_record: &ConnRecord) {
    if let Some(dispatcher) = TLS_DISPATCHER.get() {
        let _ = dispatcher.dispatch(Event::Tls((tls.clone(), conn_record.clone())), None);
    }
}

#[filter("dns")]
fn dns_cb(dns: &DnsTransaction, conn_record: &ConnRecord) {
    if let Some(dispatcher) = DNS_DISPATCHER.get() {
        let _ = dispatcher.dispatch(Event::Dns((dns.clone(), conn_record.clone())), None);
    }
}

#[retina_main(2)]
fn main() {
    let args = Args::parse();
    let config = load_config(&args.config);

    let tls_core_ids: Vec<CoreId> = args.tls_worker_cores
        .iter()
        .map(|&core| CoreId(core))
        .collect();

    let dns_core_ids: Vec<CoreId> = args.dns_worker_cores
        .iter()
        .map(|&core| CoreId(core))
        .collect();

    println!("=== Configuration ===");
    println!("Config file: {:?}", args.config);
    println!("TLS channel size: {}", args.tls_channel_size);
    println!("DNS channel size: {}", args.dns_channel_size);
    println!("TLS Core Ids: {:?}", tls_core_ids);
    println!("DNS Core Ids: {:?}", dns_core_ids);
    println!("=====================\n");

    let tls_dispatcher = Arc::new(ChannelDispatcher::new(ChannelMode::Shared, args.tls_channel_size));
    let dns_dispatcher = Arc::new(ChannelDispatcher::new(ChannelMode::Shared, args.dns_channel_size));

    TLS_DISPATCHER
        .set(tls_dispatcher.clone())
        .map_err(|_| "Failed to set TLS dispatcher")
        .unwrap();
    DNS_DISPATCHER
        .set(dns_dispatcher.clone())
        .map_err(|_| "Failed to set DNS dispatcher")
        .unwrap();

    DedicatedWorkerThreadSpawner::new()
        .set_cores(tls_core_ids)
        .set_dispatcher(tls_dispatcher.clone())
        .set(|event: Event| {
            if let Event::Tls((_tls, _conn_record)) = event {
                // add handler here 
            }
        })
        .run();

    DedicatedWorkerThreadSpawner::new()
        .set_cores(dns_core_ids)
        .set_dispatcher(dns_dispatcher.clone())
        .set(|event: Event| {
            if let Event::Dns((_dns, _conn_record)) = event {
                // add handler here 
            }
        })
        .run();

    
    let mut runtime: Runtime<SubscribedWrapper> = Runtime::new(config, filter).unwrap();
    runtime.run();

    tls_dispatcher
        .stats()
        .waiting_completion(tls_dispatcher.receivers());
    dns_dispatcher
        .stats()
        .waiting_completion(dns_dispatcher.receivers());

    println!("=== TLS Stats ===");
    tls_dispatcher.stats().print();

    println!("=== DNS Stats ===");
    dns_dispatcher.stats().print();
}
