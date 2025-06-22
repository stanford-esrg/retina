use retina_core::{config::default_config, Runtime, CoreId};
use retina_datatypes::{ConnRecord, DnsTransaction, TlsHandshake};
use retina_filtergen::{filter, retina_main};
use retina_multicore::{ChannelDispatcher, ChannelMode, SharedWorkerThreadSpawner};
use std::sync::{OnceLock, Arc};

static TLS_DISPATCHER: OnceLock<Arc<ChannelDispatcher<Event>>> = OnceLock::new();
static DNS_DISPATCHER: OnceLock<Arc<ChannelDispatcher<Event>>> = OnceLock::new();

#[derive(Clone)]
enum Event {
    Tls((TlsHandshake, ConnRecord)),
    Dns((DnsTransaction, ConnRecord)),
}

#[filter("tls")]
fn tls_cb(tls: &TlsHandshake, conn_record: &ConnRecord, _rx_core: &CoreId) {
    if let Some(dispatcher) = TLS_DISPATCHER.get() {
        dispatcher.dispatch(
            Event::Tls((tls.clone(), conn_record.clone())),
            None,
        );
    }
}

#[filter("dns")]
fn dns_cb(dns: &DnsTransaction, conn_record: &ConnRecord, _rx_core: &CoreId) {
    if let Some(dispatcher) = DNS_DISPATCHER.get() {
        dispatcher.dispatch(
            Event::Dns((dns.clone(), conn_record.clone())),
            None,
        );
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

    let _ = TLS_DISPATCHER.set(tls_dispatcher.clone());
    let _ = DNS_DISPATCHER.set(dns_dispatcher.clone());

    SharedWorkerThreadSpawner::new()
        .set_cores(vec![1, 2, 3])
        .add_dispatcher(
            tls_dispatcher,
            |event: Event| {
                if let Event::Tls((tls, conn_record)) = event {
                    println!("TLS SNI: {}, metrics: {:?}", tls.sni(), conn_record);
                }
            },
        )
        .add_dispatcher(
            dns_dispatcher,
            |event: Event| {
                if let Event::Dns((dns, conn_record)) = event {
                    println!("DNS query domain: {}, metrics: {:?}", dns.query_domain(), conn_record);
                }
            },
        )
        .run();

    let config = default_config();
    let mut runtime: Runtime<SubscribedWrapper> = Runtime::new(config, filter).unwrap();
    runtime.run();
}
