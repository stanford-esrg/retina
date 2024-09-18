use lazy_static::lazy_static;
use retina_core::{CoreId, FiveTuple};
use retina_datatypes::*;
use std::sync::RwLock;

use retina_filtergen::subscription;

lazy_static! {
    static ref CYCLES: RwLock<u64> = RwLock::new(0);
    static ref HTTP: RwLock<u64> = RwLock::new(0);
    static ref TCP: RwLock<u64> = RwLock::new(0);
    static ref IPDST: RwLock<u64> = RwLock::new(0);
    static ref IPSRC: RwLock<u64> = RwLock::new(0);
    static ref ETH: RwLock<u64> = RwLock::new(0);
}

#[allow(dead_code)]
fn http_cb(
    http: &HttpTransaction,
    five_tuple: &FiveTuple,
    _core_id: &CoreId,
    _ethertype: &EtherTCI,
) {
    let http = &**http;
    println!("http_cb - {:?}: {:?}", five_tuple, http);
}

#[allow(dead_code)]
fn conn_cb(conn: &Connection, http: &HttpTransaction) {
    println!("conn_cb - {:?}: {:?}", conn, http);
}

#[allow(dead_code)]
fn conn_list_cb(list: &SessionList, five_tuple: &FiveTuple) {
    println!("conn_list_cb - {:?}: {:?}", five_tuple, list);
}

#[allow(dead_code)]
fn conn_multi_cb(conn: &Connection, list: &SessionList, http: &HttpTransaction) {
    println!("conn_multi_cb - {:?}, {:?}, {:?}", conn, list, http);
}

#[allow(dead_code)]
fn conn_dns_cb(conn: &Connection) {
    println!("conn_dns_cb - {:?}", conn);
}

#[allow(dead_code)]
fn packet_cb(pkt: &ZcFrame, _core_id: &retina_core::CoreId, _ether_tci: &EtherTCI) {
    println!("packet_cb - {:?}", pkt.data());
}

#[allow(dead_code)]
fn tls_cb(tls: &TlsHandshake) {
    println!("tls_cb - {:?}", tls);
}

#[allow(dead_code)]
fn dns_cb(dns: &DnsTransaction) {
    println!("dns_cb - {:?}", dns);
}

#[allow(dead_code)]
fn quic_cb(quic: &QuicStream) {
    println!("quic_cb - {:?}", quic);
}

pub(crate) fn print() {
    // println!("TCP: {}", *TCP.read().unwrap());
    // println!("HTTP: {}", *HTTP.read().unwrap());
}

#[subscription("/home/tcr6/retina/examples/basic/filter_out.toml")]
fn test() {}
