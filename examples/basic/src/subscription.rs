use retina_core::conntrack::conn_id::FiveTuple;
use retina_core::conntrack::pdu::{L4Context, L4Pdu};
use retina_core::conntrack::ConnTracker;
use retina_core::memory::mbuf::Mbuf;
use retina_core::protocols::stream::{ConnParser, Session, ConnData};
use retina_core::subscription::{Subscribable, Subscription, Trackable};
use retina_core::filter::actions::*;
use retina_datatypes::*;

use retina_filtergen::subscription;

fn callback1(subscribed: Subscribed) {

}

fn callback2(subscribed: Subscribed) {

}

#[subscription("/home/trossman/retina/examples/basic/filter.toml")]
fn test() {}