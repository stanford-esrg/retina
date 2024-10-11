#![allow(clippy::needless_doctest_main)]
// #![warn(missing_docs)]

//! An ergonomic framework for high speed network traffic analysis on commodity hardware.
//!
//! Retina provides a simple filter and callback interface that lets users subscribe to network
//! traffic in real-time and run user-defined analysis code in a standard software environment. It
//! is a passive analysis framework that supports access to network traffic at one of three
//! abstraction levels:
//!
//! - Individual packets
//! - Reassembled connections
//! - Parsed application-layer sessions
//! - Static (inferrable at first packet and constant throughout the connection)
//!
//! Retina is designed with a focus on performance in real-world, high-volume network environments
//! (e.g., full-network or full-uplink analysis). It employs an efficient filtering mechanism to
//! discard out-of-scope traffic, and is not specifically geared towards deep inspection of all
//! packets (although it can be customized to do so). See [retina_filtergen](../retina_filtergen)
//! for filter syntax and usage.
//!
//! The framework currently comes with built-in support for several [subscribable
//! datatypes](../datatypes). Additional datatypes are welcome and encouraged.
//!
//! The following example shows a simple Retina application with two subscriptions, which print
//! (1) parsed TLS handshakes and (2) parsed DNS transactions to stdout:
//!
//! ```rust
//! /*
//! use retina_core::config::default_config;
//! use retina_core::subscription::TlsHandshake;
//! use retina_core::Runtime;
//! use retina_filtergen::filter;
//!
//! #[filter("tls.sni ~ '^.*\\.com$'")]
//! fn log_tls(tls: &TlsHandshake) {
//!      println!("{:?}", tls);
//! }
//!
//! #[filter("dns")]
//! fn log_tls(dns: &DnsTransaction) {
//!      println!("{:?}", dns);
//! }
//!
//! #[retina_main(2)] // Framework expects callbacks
//! fn main() {
//!     let cfg = default_config();
//!     let mut runtime<SubscribedWrapper> = Runtime::new(cfg, filter, callback).unwrap();
//!     runtime.run();
//! }
//!  */
//! ```
//!
//! For more on writing Retina programs, see [GitHub](https://github.com/stanford-esrg/retina).
//!

#[macro_use]
mod timing;
pub mod config;
pub mod conntrack;
#[doc(hidden)]
#[allow(clippy::all)]
mod dpdk;
// The filter module must be public to be accessible by the filter_gen procedural macro crate.
// However, module functions should be opaque to users, so documentation is hidden by default.
#[doc(hidden)]
pub mod filter;
pub mod lcore;
pub mod memory;
mod port;
pub mod protocols;
mod runtime;
pub mod subscription;
pub mod utils;

pub use self::conntrack::conn_id::{ConnId, FiveTuple};
pub use self::conntrack::pdu::L4Pdu;
pub use self::lcore::CoreId;
pub use self::memory::mbuf::Mbuf;
pub use self::runtime::Runtime;

pub use dpdk::rte_lcore_id;
pub use dpdk::rte_rdtsc;

#[macro_use]
extern crate pest_derive;
#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate maplit;
