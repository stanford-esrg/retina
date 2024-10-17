#![allow(clippy::needless_doctest_main)]
// #![warn(missing_docs)]

//! An ergonomic framework for high speed network traffic analysis on commodity hardware.
//!
//! Retina provides a simple filter and callback interface that lets users subscribe to network
//! traffic in real-time and run user-defined analysis code in a standard software environment. It
//! is a passive analysis framework that supports access to network traffic at one of four
//! abstraction levels:
//!
//! - Individual packets
//! - Reassembled connections
//! - Parsed application-layer sessions
//! - Static (inferrable at first packet and constant throughout the connection)
//!
//! Retina is designed with a focus on performance in real-world, high-volume network environments
//! (e.g., full-network or full-uplink analysis). It employs an efficient filtering mechanism to
//! discard out-of-scope traffic. Due to performance, is not specifically geared towards deep
//! inspection of all packets, though it can be customized to do so with sampling.
//!
//! For filter and callback syntax and usage, see [retina_filtergen](../retina_filtergen).
//! All built-in subscribable datatypes are defined in [retina_datatypes](../retina_datatypes).
//! Additional datatypes in this crate are welcome and encouraged!
//!
//! The following example shows a simple Retina application with two subscriptions, which print
//! (1) parsed TLS handshakes and (2) parsed DNS transactions to stdout:
//!
//! ```rust
//! use retina_core::config::default_config;
//! use retina_core::Runtime;
//! use retina_filtergen::{retina_main, filter};
//! use retina_datatypes::*;
//!
//! // Specify a subscription: filter, datatype(s), and callback. The filter determines what
//! // subset of traffic is delivered to the callback. The datatype(s) determine what data is
//! // delivered (here, a parsed TLS handshake). Datatypes are defined in the retina_datatypes
//! // crate and must be passed by immutable reference.
//! // The callback is executed when the filter (here, TLS connection with matching sni)
//! // is matched and the specified data is ready to be delivered (here, when the TLS handshake
//! // is fully parsed).
//! #[filter("tls.sni ~ '^.*\\.com$'")]
//! fn log_tls(tls: &TlsHandshake) {
//!      println!("{:?}", tls);
//! }
//!
//! // A Retina application consists of one or more subscriptions.
//! // Define other subscriptions in the same file.
//! #[filter("dns")]
//! fn log_dns(dns: &DnsTransaction) {
//!      println!("{:?}", dns);
//! }
//!
//! // When using the `filter` macro to identify subscriptions, include the
//! // `retina_main` attribute with the number of expected subscriptions.
//! #[retina_main(2)]
//! fn main() {
//!     // Specify the runtime config (default or from a config file)
//!     let cfg = default_config();
//!     // SubscribedWrapper is the type generated at compile-time to "wrap" all
//!     // data tracking and delivering functionality, while `filter` wraps all filtering.
//!     let runtime::<SubscribedWrapper> = Runtime::new(cfg, filter).unwrap();
//!     // Starts Retina
//!     runtime.run();
//! }
//! ```
//!
//! For programs that require many filters (e.g., searching for 100s of attack signatures), using
//! the [subscription](retina_filtergen::subscription) macro to specify an input TOML file may
//! be preferable to specifying each subscription individually as above.
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
#[doc(hidden)]
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
