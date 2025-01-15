use prometheus_client::encoding::EncodeLabelSet;
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::family::Family;
use prometheus_client::registry::Registry;
use retina_core::config::load_config;
use retina_core::{stats::register_base_prometheus_registry, CoreId, Runtime};
use retina_datatypes::*;
use retina_filtergen::{filter, retina_main};

use clap::Parser;
use std::path::PathBuf;
use std::sync::LazyLock;

#[derive(Parser, Debug)]
struct Args {
    #[clap(short, long, parse(from_os_str), value_name = "FILE")]
    config: PathBuf,
}

// Note: Using unbounded and high cardinality label set (like website field here) is bad practice
// and can lead to high memory and disk usage in Prometheus. This is just an example.
#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct Labels {
    protocol: &'static str,
    website: String,
    core_id: u32,
}

static FAMILY: LazyLock<Family<Labels, Counter>> = LazyLock::new(Family::default);

fn init() {
    let mut r = Registry::default();
    r.register(
        "myapp_site_hits",
        "Number of callback calls per each website and protocol",
        FAMILY.clone(),
    );
    register_base_prometheus_registry(r);
}

fn write_result(protocol: &'static str, website: String, core_id: &CoreId) {
    if website.is_empty() {
        return;
    } // Would it be helpful to count these?
    FAMILY
        .get_or_create(&Labels {
            protocol,
            website,
            core_id: core_id.raw(),
        })
        .inc();
}

#[filter("dns")]
fn dns_cb(dns: &DnsTransaction, core_id: &CoreId) {
    let query_domain = (*dns).query_domain().to_string();
    write_result("dns", query_domain, core_id);
}

#[filter("http")]
fn http_cb(http: &HttpTransaction, core_id: &CoreId) {
    let uri = (*http).uri().to_string();
    write_result("http", uri, core_id);
}

#[filter("tls")]
fn tls_cb(tls: &TlsHandshake, core_id: &CoreId) {
    let sni = (*tls).sni().to_string();
    write_result("tls", sni, core_id);
}

#[filter("quic")]
fn quic_cb(quic: &QuicStream, core_id: &CoreId) {
    let sni = quic.tls.sni().to_string();
    write_result("quic", sni, core_id);
}

#[retina_main(4)]
fn main() {
    init();
    let args = Args::parse();
    let config = load_config(&args.config);
    let mut runtime: Runtime<SubscribedWrapper> = Runtime::new(config, filter).unwrap();
    runtime.run();
}
