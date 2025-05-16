use std::path::Path;
use std::net::Ipv4Addr;

use serde::Serialize;

#[derive(Serialize)]
struct SubscriptionSpec {
    filter: String,
    datatypes: Vec<String>,
    callback: String,
}

impl SubscriptionSpec {
    fn new(addr: Ipv4Addr) -> Self {
        Self {
            filter: format!("ipv4.addr = {}", addr),
            datatypes: vec!["ConnRecord".to_string(), "FilterStr".to_string()], // FIX to whatever the right dtypes are
            callback: format!("ip_cb"),
        }
    }
}

#[derive(Serialize)]
struct Subscriptions {
    subscriptions: Vec<SubscriptionSpec>,
}

impl Subscriptions {
    fn toml_contents(&self) -> Result<String, Box<dyn std::error::Error>> {
        Ok(toml::to_string_pretty(self)?)
    }

    fn to_toml<P: AsRef<Path>>(&self, path: P) -> Result<(), Box<dyn std::error::Error>> {
        let toml_text = self.toml_contents()?;
        std::fs::write(path, toml_text)?;
        Ok(())
    }
}

// evenly shard Ipv4 address space into n buckets
fn shard_ipv4_addr_space(n: u32) -> Vec<Ipv4Addr> {
    assert!(n > 0, "n must be > 0");

    // 2^32 possible IPv4 addresses
    const TOTAL: u64 = 1u64 << 32;
    let step: u64 = TOTAL / n as u64;

    (0..n)
        .map(|i| {
            let addr_as_u32 = (i as u64 * step) as u32;
            Ipv4Addr::from(addr_as_u32)
        })
        .collect()
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);

    // num subs: default is 10
    let n = args
        .next()
        .and_then(|s| s.parse::<u32>().ok())
        .unwrap_or(10);

    // println!("{}", n);

    // default file to write subs to is "spec.toml"
    // TODO: fix this later to allow someone to pass in a filename?
    // let output_path = args.next().unwrap_or_else(|| "spec.toml".into());
    let output_path = "spec.toml";

    let mut ip_addrs = shard_ipv4_addr_space(n);
    // (REMOVE LATER) manually add this IP address from small_flows.pcap to ensure we have at least 1 addr that matches the filter : 192.168.3.131
    ip_addrs.push(Ipv4Addr::new(192, 168, 3, 131));

    let subs = Subscriptions {
        subscriptions: ip_addrs.into_iter().map(SubscriptionSpec::new).collect(),
    };

    subs.to_toml(&output_path)?;

    println!("Generated {} with {} subscriptions", output_path, n);
    Ok(())
}
