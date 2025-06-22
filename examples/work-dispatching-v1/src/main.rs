use retina_core::{config::load_config, Runtime, CoreId};
use retina_datatypes::{ConnRecord, DnsTransaction, TlsHandshake};
use retina_filtergen::{filter, retina_main};
use retina_multicore::{ChannelDispatcher, ChannelMode, DedicatedWorkerThreadSpawner};
use std::sync::{OnceLock, Arc};

static TLS_DISPATCHER: OnceLock<Arc<ChannelDispatcher<Event>>> = OnceLock::new();
static DNS_DISPATCHER: OnceLock<Arc<ChannelDispatcher<Event>>> = OnceLock::new();

#[derive(Clone)]
enum Event {
    Tls((TlsHandshake, ConnRecord)),
    Dns((DnsTransaction, ConnRecord)),
}

#[filter("tls")]
fn tls_cb(tls: &TlsHandshake, conn_record: &ConnRecord, rx_core: &CoreId) {
    if let Some(dispatcher) = TLS_DISPATCHER.get() {
        dispatcher.dispatch(
            Event::Tls((tls.clone(), conn_record.clone())),
            Some(rx_core),
        );
    }
}

#[filter("dns")]
fn dns_cb(dns: &DnsTransaction, conn_record: &ConnRecord, rx_core: &CoreId) {
    if let Some(dispatcher) = DNS_DISPATCHER.get() {
        dispatcher.dispatch(
            Event::Dns((dns.clone(), conn_record.clone())),
            Some(rx_core),
        );
    }
}

#[retina_main(2)]
fn main() {
    let config = load_config("./configs/offline.toml");
    let rx_cores = config.get_all_rx_core_ids();

    let tls_dispatcher = Arc::new(ChannelDispatcher::new(
        ChannelMode::PerCore(rx_cores.clone()),
        1024,
    ));
   
    let dns_dispatcher = Arc::new(ChannelDispatcher::new(
        ChannelMode::PerCore(rx_cores.clone()),
        512,
    ));

    let _ = TLS_DISPATCHER.set(tls_dispatcher.clone());
    let _ = DNS_DISPATCHER.set(dns_dispatcher.clone());

    DedicatedWorkerThreadSpawner::new()
        .set_cores(vec![1, 2])
        .set_dispatcher(tls_dispatcher)
        .set(|event: Event| {
            if let Event::Tls((tls, conn_record)) = event {
                println!("TLS SNI: {}, conn. metrics: {:?}", tls.sni(), conn_record);
            }
        })
        .run();

    DedicatedWorkerThreadSpawner::new()
        .set_cores(vec![3])
        .set_dispatcher(dns_dispatcher)
        .set(|event: Event| {
            if let Event::Dns((dns, conn_record)) = event {
                println!(
                    "DNS query domain: {}, conn. metrics: {:?}",
                    dns.query_domain(),
                    conn_record
                );
            }
        })
        .run();

    let mut runtime: Runtime<SubscribedWrapper> = Runtime::new(config, filter).unwrap();
    runtime.run();
}
