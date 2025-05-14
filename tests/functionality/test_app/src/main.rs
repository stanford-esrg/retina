use retina_core::{config::default_config, Runtime};
use retina_datatypes::{ConnRecord, DnsTransaction, TlsHandshake};
use retina_filtergen::{filter, retina_main};

// Goals for application:
// Take in a packet capture file... run retina application using data from that file
// Application should count amount of times callback is invoked
// Also include matching of five_tuples, etc. (will be in main application I'm designing so logic is the same)
// Format results the same as input file (expected format)
// Output passed/not passed and results in terminal and also in a file? (appname_configfilename_output.txt)
// Do we want to be able to save output multiple times? (multiple files like test_app_output_1.txt, etc.)



#[filter("tls")]
fn tls_cb(tls: &TlsHandshake, conn_record: &ConnRecord) {
    println!("Tls SNI: {}, conn. metrics: {:?}", tls.sni(), conn_record);
}

#[filter("dns")]
fn dns_cb(dns: &DnsTransaction, conn_record: &ConnRecord) {
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
