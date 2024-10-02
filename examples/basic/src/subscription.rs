use lazy_static::lazy_static;
use retina_core::FiveTuple;
use retina_datatypes::*;
use std::sync::RwLock;

use retina_filtergen::subscription;

lazy_static! {
    static ref CYCLES: RwLock<u64> = RwLock::new(0);
    static ref HTTP: RwLock<u64> = RwLock::new(0);
    static ref CONN: RwLock<u64> = RwLock::new(0);
    static ref IPDST: RwLock<u64> = RwLock::new(0);
    static ref IPSRC: RwLock<u64> = RwLock::new(0);
    static ref ETH: RwLock<u64> = RwLock::new(0);
}

#[allow(dead_code)]
#[allow(unused_variables)]
fn http_cb(
    http: &HttpTransaction,
    five_tuple: &FiveTuple,
) {
    let http = &**http;
    println!("http_cb - {:?}: {:?}", five_tuple, http);
}

#[allow(dead_code)]
#[allow(unused_variables)]
fn conn_cb(conn: &Connection, http: &HttpTransaction) {
    println!("conn_cb - {:?}: {:?}", conn, http);
}

#[allow(dead_code)]
#[allow(unused_variables)]
fn conn_list_cb(list: &SessionList, conn: &Connection, filter_str: &FilterStr) {
    // println!("conn_list_cb - {:?}: {:?}", conn, list);
    println!("conn_list_cb - {:?}: {:?}, {}", conn, list, filter_str);
    *CONN.write().unwrap() += 1;
}

#[allow(unused_variables)]
#[allow(dead_code)]
fn conn_multi_cb(conn: &Connection, list: &SessionList, http: &HttpTransaction) {
    println!("conn_multi_cb - {:?}, {:?}, {:?}", conn, list, http);
}

#[allow(dead_code)]
#[allow(unused_variables)]
fn conn_dns_cb(conn: &Connection) {
    println!("conn_dns_cb - {:?}", conn);
}

#[allow(dead_code)]
#[allow(unused_variables)]
fn packet_cb(pkt: &ZcFrame, _core_id: &retina_core::CoreId, filter_str: &FilterStr) {
    println!("packet_cb - {:?}", pkt.data());
}

#[allow(dead_code)]
#[allow(unused_variables)]
fn tls_cb(tls: &TlsHandshake) {
    println!("tls_cb - {:?}", tls);
}

#[allow(dead_code)]
#[allow(unused_variables)]
fn dns_cb(dns: &DnsTransaction) {
    println!("dns_cb - {:?}", dns);
}

#[allow(dead_code)]
#[allow(unused_variables)]
fn quic_cb(quic: &QuicStream) {
    println!("quic_cb - {:?}", quic);
}

pub(crate) fn print() {
    println!("CONN: {}", *CONN.read().unwrap());
    // println!("HTTP: {}", *HTTP.read().unwrap());
}

#[allow(dead_code)]
#[allow(unused_variables)]
#[subscription("/home/tcr6/retina/examples/basic/filter_out.toml")]
fn test() {}
