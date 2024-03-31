use retina_core::conntrack::conn_id::FiveTuple;
use retina_core::conntrack::pdu::{L4Context, L4Pdu};
use retina_core::conntrack::ConnTracker;
use retina_core::memory::mbuf::Mbuf;
use retina_core::protocols::stream::{ConnParser, Session, ConnData};
use retina_core::subscription::{Subscribable, Subscription, Trackable};
use retina_core::filter::actions::*;
use retina_datatypes::*;
use lazy_static::lazy_static;
use std::sync::RwLock;

use retina_filtergen::subscription;

fn max_cb(_subscribed: Subscribed) {
}

fn netflix_cb(_subscribed: Subscribed) {
}

#[subscription("/home/tcr6/retina/examples/video/filter.toml")]
fn test() {}

pub(crate) fn print() {}
