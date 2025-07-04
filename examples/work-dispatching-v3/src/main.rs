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
    config: PathBuf
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

    let tls_dispatcher = Arc::new(ChannelDispatcher::new(ChannelMode::Shared, 1024));

    let dns_dispatcher = Arc::new(ChannelDispatcher::new(ChannelMode::Shared, 512));

    TLS_DISPATCHER
        .set(tls_dispatcher.clone())
        .map_err(|_| "Failed to set TLS dispatcher")
        .unwrap();
    DNS_DISPATCHER
        .set(dns_dispatcher.clone())
        .map_err(|_| "Failed to set DNS dispatcher")
        .unwrap();

    DedicatedWorkerThreadSpawner::new()
        .set_cores(vec![CoreId(1), CoreId(2)])
        .set_dispatcher(tls_dispatcher.clone())
        .set(|event: Event| {
            if let Event::Tls((_tls, _conn_record)) = event {
                // add handler here 
            }
        })
        .run();

    DedicatedWorkerThreadSpawner::new()
        .set_cores(vec![CoreId(3)])
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
