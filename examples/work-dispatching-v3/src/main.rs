use retina_core::{config::default_config, Runtime, CoreId};
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
fn tls_cb(tls: &TlsHandshake, conn_record: &ConnRecord) {
    if let Some(dispatcher) = TLS_DISPATCHER.get() {
        if let Err(e) = dispatcher.dispatch(
            Event::Tls((tls.clone(), conn_record.clone())),
            None,
        ) {
            eprintln!("TLS dispatch error: {}", e);
        }
    }
}

#[filter("dns")]
fn dns_cb(dns: &DnsTransaction, conn_record: &ConnRecord) {
    if let Some(dispatcher) = DNS_DISPATCHER.get() {
        if let Err(e) = dispatcher.dispatch(
            Event::Dns((dns.clone(), conn_record.clone())),
            None,
        ) {
            eprintln!("DNS dispatch error: {}", e);
        }
    }
}

#[retina_main(2)]
fn main() {
    let tls_dispatcher = Arc::new(ChannelDispatcher::new(
        ChannelMode::Shared,
        1024,
    ));
   
    let dns_dispatcher = Arc::new(ChannelDispatcher::new(
        ChannelMode::Shared,
        512,
    ));

    TLS_DISPATCHER.set(tls_dispatcher.clone())
        .map_err(|_| "Failed to set TLS dispatcher")
        .unwrap();
    DNS_DISPATCHER.set(dns_dispatcher.clone())
        .map_err(|_| "Failed to set DNS dispatcher")
        .unwrap();


    DedicatedWorkerThreadSpawner::new()
        .set_cores(vec![CoreId(1), CoreId(2)])
        .set_dispatcher(tls_dispatcher)
        .set(|event: Event| {
            if let Event::Tls((tls, conn_record)) = event {
                println!("TLS SNI: {}, conn. metrics: {:?}", tls.sni(), conn_record);
            }
        })
        .run();

    DedicatedWorkerThreadSpawner::new()
        .set_cores(vec![CoreId(3)])
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

    let config = default_config();
    let mut runtime: Runtime<SubscribedWrapper> = Runtime::new(config, filter).unwrap();
    runtime.run();
}
