use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use retina_core::filter::flow_drop::{install_drop_flow};
use retina_core::FiveTuple;
use retina_core::port::PortId;

fn main() {
    // Create dummy FiveTuple (IPv4 TCP example)
    let tuple = FiveTuple {
        orig: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)), 12345),
        resp: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 80),
        proto: libc::IPPROTO_TCP as usize,
    };

    // Use PortId instead of Port
    let s = String::from("3b:00");
    let port_id = PortId::new_from_device(s);

    // Try to call your function
    match install_drop_flow(&port_id, &tuple) {
        Ok(_) => println!("Flow installed successfully."),
        Err(e) => eprintln!("Error installing flow: {e}"),
    }
}

