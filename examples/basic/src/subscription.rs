use retina_core::conntrack::conn_id::FiveTuple;
use retina_core::conntrack::pdu::L4Pdu;
use retina_core::memory::mbuf::Mbuf;
use retina_core::protocols::stream::{ConnParser, Session, ConnData};
use retina_core::subscription::{Subscribable, Subscription, Trackable};
use retina_core::filter::actions::*;
use retina_datatypes::*;
use lazy_static::lazy_static;
use std::sync::RwLock;

use retina_datatypes::{HttpTransaction, Connection};

use retina_filtergen::subscription;

lazy_static!(
    static ref CYCLES: RwLock<u64> = RwLock::new(0);
    static ref HTTP: RwLock<u64> = RwLock::new(0);
    static ref TCP: RwLock<u64> = RwLock::new(0);
    static ref IPDST: RwLock<u64> = RwLock::new(0);
    static ref IPSRC: RwLock<u64> = RwLock::new(0);
    static ref ETH: RwLock<u64> = RwLock::new(0);
);

#[allow(dead_code)]
fn http_cb(http: &HttpTransaction) {
    let http = &**http;
    println!("http_cb - {:?}", http);
}

#[allow(dead_code)]
fn conn_cb(conn: &Connection) {
    println!("conn_cb - {:?}", conn);
}

#[allow(dead_code)]
fn conn_dns_cb(conn: &Connection) {
    println!("conn_dns_cb - {:?}", conn);
}

#[allow(dead_code)]
fn packet_cb(pkt: &ZcFrame) {
    println!("pkt - {:?}", pkt);
}

pub(crate) fn print() {
    // println!("TCP: {}", *TCP.read().unwrap());
    // println!("HTTP: {}", *HTTP.read().unwrap());
}

#[subscription("/home/trossman/retina/examples/basic/filter_out.toml")]
fn test() {}