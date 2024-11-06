use retina_core::{config::default_config, Runtime};
use retina_datatypes::{ConnRecord, DnsTransaction, PacketList, TlsHandshake};
use retina_filtergen::{filter, retina_main};

#[filter("tls")]
fn tls_cb(tls: &TlsHandshake, conn_record: &ConnRecord, pkt_list: &PacketList) {
    println!("Tls SNI: {}, conn. metrics: {:?}", tls.sni(), conn_record);
}

#[filter("dns")]
fn dns_cb(dns: &DnsTransaction, conn_record: &ConnRecord, pkt_list: &PacketList) {
    println!(
        "DNS query domain: {}, conn. metrics: {:?}",
        dns.query_domain(),
        conn_record
    );
}

#[retina_main(2)]
fn main() {
    let config = default_config();
    let mut runtime: Runtime<SubscribedWrapper> = Runtime::new(config, filter).unwrap();
    runtime.run();
}
