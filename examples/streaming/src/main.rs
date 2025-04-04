use retina_core::{config::default_config, Runtime};
use retina_datatypes::ConnRecord;
use retina_filtergen::{filter, retina_main, streaming};

#[filter("tls")]
#[streaming("seconds=10")]
fn tls_cb(conn_record: &ConnRecord) -> bool {
    println!("Conn. metrics: {:?}", conn_record);
    true
}

#[retina_main(1)]
fn main() {
    let config = default_config();
    let mut runtime: Runtime<SubscribedWrapper> = Runtime::new(config, filter).unwrap();
    runtime.run();
}
