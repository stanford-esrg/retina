#![allow(clippy::needless_doctest_main)]
//! A macro for defining subscriptions in Retina.
//!
//! # Specifying Subscriptions in a .rs File
//!
//! [`filter`](macro@self::filter) is an attribute macro that parses a user-defined filter
//! expression to generate sub-filters that are statically inlined at each processing layer. This
//! verifies filter expressions at compile time and avoids overheads associated with interpreting
//! filters at runtime. The `filter` attribute macro must be tied to the callback requested.
//!
//! [`retina_main`](macro@self::retina_main) is an attribute macro that must be used alongside
//! [`filter`](macro@self::filter). It indicates to the framework how many subscriptions to expect.
//!
//! ## Usage
//! ```rust,no_run
//! use retina_core::config::default_config;
//! use retina_core::Runtime;
//! use retina_filtergen::{filter, retina_main};
//! use retina_datatypes::*;
//!
//! #[filter("ipv4 and tcp.port >= 100")]
//! fn log_tcp(conn: &ConnRecord) { // Callback; datatype(s) by reference
//!    println!("{:#?}", conn);
//! }
//!
//! #[filter("tls.sni ~ 'netflix'")]
//! fn log_tls(conn: &ConnRecord, tls: &TlsHandshake) {
//!    println!("{:#?}, {:#?}", conn, tls);
//! }
//!
//! #[retina_main(2)] // 2 subscriptions expected
//! fn main() {
//!    let cfg = default_config();
//!    // \note SubscribedWrapper is the structure built at compile-time to
//!    // 'wrap' all requested data. It must be specified as the generic parameter to Runtime.
//!    let mut runtime: Runtime<SubscribedWrapper> = Runtime::new(cfg, filter).unwrap();
//!    runtime.run();
//! }
//! ```
//!
//! # Specifying Subscriptions in TOML File
//!
//! [`subscription`](macro@self::subscription) is an attribute macro that allows users to specify
//! a list of subscriptions from an input file. This may be useful, for example, for programs that require
//! a large number of filters to be applied to the same callback.
//!
//! Input TOML files should be a list of `subscriptions`, each of which has `filter`, `datatypes`,
//! and `callback` specified. The datatypes in the TOML file must match the order and names of the
//! datatypes in the callbacks in code.
//!
//! ## Usage
//! ```toml
//![[subscriptions]]
//! filter = "(http.user_agent = '/mm.jpg') and (tcp.dst_port = 80 or tcp.dst_port = 8080)"
//! datatypes = [
//!     "HttpTransaction",
//!     "FilterStr",
//! ]
//! callback = "http_cb"
//!
//![[subscriptions]]
//! filter = "http.user_agent = 'HttpBrowser/1.0'"
//! datatypes = [
//!     "HttpTransaction",
//!     "FilterStr",
//! ]
//! callback = "http_cb"
//! ```
//!
//! ```rust,ignore
//! use retina_core::config::default_config;
//! use retina_core::Runtime;
//! use retina_filtergen::subscription;
//! use retina_datatypes::*;
//!
//! fn http_cb(http: &HttpTransaction, matched_filter: &FilterStr) {
//!    println!("Matched {} with {:#?}", matched_filter, http);
//! }
//!
//! #[subscription("examples/XX/spec.toml")]
//! fn main() {
//!    let cfg = default_config();
//!    let mut runtime: Runtime<SubscribedWrapper> = Runtime::new(cfg, filter).unwrap();
//!    runtime.run();
//! }
//! ```
//!
//! # Datatype syntax
//! All subscribed datatypes -- parameters to callbacks -- must be requested by reference.
//! Supported datatypes are defined in the [retina_datatypes](../retina_datatypes) crate.
//!
//! # Filter syntax
//! The Retina filter syntax is similar to that of [Wireshark display
//! filters](https://wiki.wireshark.org/DisplayFilters). However, Retina is capable of filtering on
//! live traffic for online analysis, whereas display filters can only be applied for offline
//! analysis.
//!
//! A filter expression is a logical expression of constraints on attributes of the input traffic.
//! Each constraint is either a binary predicate that compares the value of an entity's attribute
//! with a constant, or a unary predicate that matches against the entity itself.
//!
//! ## Protocols
//! All protocol identifiers are valid as long as Retina contains an appropriate [protocol
//! module](../retina_core/protocols) of the same name. The [`filter`](macro@self::filter) macro
//! automatically generates filtering code using structs defined in the protocol's corresponding
//! parser module. The exception to this is `ethernet`, which Retina filters for by default.
//!
//! For example, [`ipv4`](../retina_core/protocols/packet/ipv4) and
//! [`tls`](../retina_core/protocols/stream/tls) are filterable protocols because they are both
//! protocol modules included in Retina.
//!
//! Retina will also automatically expand filter expressions to their fully-qualified form. For
//! example, the filter `tcp` is equivalent to `(ipv4 and tcp) or (ipv6 and tcp)`.
//!
//! ## Fields
//! All field identifiers are valid as long as Retina exposes a public accessor method for the
//! corresponding protocol struct of the same name, and the method returns a supported RHS field
//! type.
//!
//! For example,
//! [`ipv4.src_addr`](../retina_core/protocols/packet/ipv4/struct.Ipv4.html#method.src_addr) and
//! [`tls.sni`](../retina_core/protocols/stream/tls/struct.Tls.html#method.sni) are both filterable
//! fields because `src_addr()` is a public method associated with the `Ipv4` struct that returns an
//! `Ipv4Addr`, and `sni()` is a public method associated with the `Tls` struct that returns a
//! `String`.
//!
//! Retina also supports two combined fields: `addr` and `port`. Logically, these are equivalent to
//! `src_addr or dst_addr` and `src_port or dst_port`, respectively, except in predicates that use
//! the `!=` comparison operator (details below).
//!
//! ## Field types (RHS values)
//! | Type          | Example            |
//! |---------------|--------------------|
//! | IPv4 address  | `1.2.3.4`          |
//! | IPv4 prefix   | `1.2.3.4/24`       |
//! | IPv6 address  | `2001:db8::1`      |
//! | IPv6 prefix   | `2001:db8::1/64`   |
//! | Integer       | `443`              |
//! | String        | `'Safari'`         |
//! | Integer range | `1024..5000`       |
//! | Byte          | `\|32 2E 30\|`       |
//!
//! ## Binary comparison operators
//! | Operator |   Alias   |         Description        | Example                         |
//! |----------|-----------|----------------------------|---------------------------------|
//! | `=`      |           | Equals                     | `ipv4.addr = 127.0.0.1`         |
//! | `!=`     | `ne`      | Not equals                 | `udp.dst_port != 53`            |
//! | `>=`     | `ge`      | Greater than or equals     | `tcp.port >= 1024`              |
//! | `<=`     | `le`      | Less than or equals        | `tls.version <= 771`            |
//! | `>`      | `gt`      | Greater than               | `ipv4.time_to_live > 64`        |
//! | `<`      | `lt`      | Less than                  | `ipv6.payload_length < 500`     |
//! | `in`     |           | In a range, or in a subnet | `ipv4.src_addr in 1.2.3.4/16`   |
//! | `~`      | `matches` | Regular expression match   | `tls.sni ~ 'netflix\\.com$'`    |
//! | `~b`     |           | Byte regular expression match | `ssh.protocol_version_ctos ~b '(?-u)^\x32\\.\x30$'` |
//! | `contains` |           | Check if right appears in left | `ssh.key_exchange_cookie_stoc contains \|15 A1\|` |
//! | `not contains` | `!contains` | Check that right doesn't appear in left | `ssh.key_exchange_cookie_stoc not contains \|15 A1\|` |
//!
//! **Possible pitfalls involving `!=`**
//!
//! Retina differs from Wireshark behavior regarding the `!=` operator. When applied to combined
//! fields (i.e., `addr` or `port`), Retina follows connection-level semantics instead of
//! packet-level semantics. For example, `tcp.port != 80` is equivalent to `tcp.src_port != 80 and
//! tcp.dst_port != 80`.
//!
//! **Regular expressions**
//!
//! Retina compiles regular expressions exactly once, using the
//! [`regex`](https://crates.io/crates/regex) and
//! [`lazy_static`](https://crates.io/crates/lazy_static) crates. As of this writing, `proc-macro`
//! crates like this one cannot export any items other than procedural macros, thus requiring
//! applications that wish to use Retina's regular expression filtering to specify `regex` and
//! `lazy_static` as dependencies. Also note that regular expressions are written as normal strings
//! in Rust, and not as [raw string
//! literals](https://doc.rust-lang.org/stable/reference/tokens.html#raw-string-literals). They are
//! allowed to match anywhere in the text, unless start (`^`) and end (`$`) anchors are used.
//!
//! **Byte regular expressions**
//!
//! Using regular expressions with bytes works similarly as with strings, except we use the
//! `regex::bytes::Regex` API from the [`bytes`](https://docs.rs/regex/latest/regex/bytes/index.html) module
//! in the [`regex`](https://crates.io/crates/regex) crate instead of the `regex::Regex` API to
//! match on bytes.
//!
//! **Contains operator**
//!
//! The `contains` operator uses the [`memchr`](https://crates.io/crates/memchr) crate to search in bytes and strings quickly.
//! Specifically, [`Finder`](https://docs.rs/memchr/latest/memchr/memmem/struct.Finder.html) from the `memmem` module
//! is used to search for the same needle in many different haystacks without the overhead from constructing the searcher.
//! For a given needle, Retina uses the [`lazy_static`](https://crates.io/crates/lazy_static) crate
//! to compile the `Finder` for this needle just once.
//!
//! ## Logical operators
//! | Operator | Alias | Description | Example                                      |
//! |----------|-------|-------------|----------------------------------------------|
//! | `and`    | `AND` | Logical AND | `tcp.port = 443 and tls`                     |
//! | `or`     | `OR`  | Logical OR  | `http.method = 'GET' or http.method = 'POST'`|
//!
//! `AND` takes precedence over `OR` in the absence of parentheses.
//!
//! Retina does not yet support the logical `NOT` operator. For some expressions, it can be
//! approximated using the `!=` binary comparison operator, taking the above mentioned pitfall into
//! consideration.

use proc_macro::TokenStream;
use quote::quote;
use retina_core::filter::ptree::*;
use retina_core::filter::*;
use std::str::FromStr;
use syn::parse_macro_input;
use utils::DELIVER;

#[macro_use]
extern crate lazy_static;

mod cache;
mod data;
mod deliver_filter;
mod packet_filter;
mod parse;
mod proto_filter;
mod session_filter;
mod utils;

use crate::cache::*;
use crate::data::*;
use crate::deliver_filter::gen_deliver_filter;
use crate::packet_filter::gen_packet_filter;
use crate::parse::*;
use crate::proto_filter::gen_proto_filter;
use crate::session_filter::gen_session_filter;

// Build a string that can be used to generate a hardware (NIC) filter at runtime.
fn get_hw_filter(packet_continue: &PTree) -> String {
    let ret = packet_continue.to_filter_string();
    let _flat_ptree =
        Filter::new(&ret).unwrap_or_else(|err| panic!("Invalid HW filter {}: {:?}", &ret, err));
    ret
}

// Returns a PTree from the given config
fn filter_subtree(input: &SubscriptionConfig, filter_layer: FilterLayer) -> PTree {
    let mut ptree = PTree::new_empty(filter_layer);

    for i in 0..input.subscriptions.len() {
        let spec = &input.subscriptions[i];
        let filter = Filter::new(&spec.filter)
            .unwrap_or_else(|err| panic!("Failed to parse filter {}: {:?}", spec.filter, err));

        let patterns = filter.get_patterns_flat();
        let deliver = Deliver {
            id: i,
            as_str: spec.as_str(),
            must_deliver: spec.datatypes.iter().any(|d| d.as_str == "FilterStr"),
        };
        ptree.add_filter(&patterns, spec, &deliver);
        DELIVER.lock().unwrap().insert(i, spec.clone());
    }

    ptree.collapse();
    println!("{}", ptree);
    ptree
}

// Generate code from the given config (all subscriptions)
// Also includes the original input (typically a callback or main function)
fn generate(input: syn::ItemFn, config: SubscriptionConfig) -> TokenStream {
    let mut statics: Vec<proc_macro2::TokenStream> = vec![];

    let packet_cont_ptree = filter_subtree(&config, FilterLayer::PacketContinue);
    let packet_continue = gen_packet_filter(
        &packet_cont_ptree,
        &mut statics,
        FilterLayer::PacketContinue,
    );

    let packet_ptree = filter_subtree(&config, FilterLayer::Packet);
    let packet_filter = gen_packet_filter(&packet_ptree, &mut statics, FilterLayer::Packet);

    let conn_ptree = filter_subtree(&config, FilterLayer::Protocol);
    let proto_filter = gen_proto_filter(&conn_ptree, &mut statics);

    let session_ptree = filter_subtree(&config, FilterLayer::Session);
    let session_filter = gen_session_filter(&session_ptree, &mut statics);

    let conn_deliver_ptree = filter_subtree(&config, FilterLayer::ConnectionDeliver);
    let conn_deliver_filter = gen_deliver_filter(
        &conn_deliver_ptree,
        &mut statics,
        FilterLayer::ConnectionDeliver,
    );
    let packet_deliver_ptree = filter_subtree(&config, FilterLayer::PacketDeliver);
    let packet_deliver_filter = gen_deliver_filter(
        &packet_deliver_ptree,
        &mut statics,
        FilterLayer::PacketDeliver,
    );

    let mut tracked_data = TrackedDataBuilder::new(&config);
    let subscribable = tracked_data.subscribable_wrapper();
    let tracked = tracked_data.tracked();

    let filter_str = get_hw_filter(&packet_cont_ptree); // Packet-level keep/drop filter

    let lazy_statics = if statics.is_empty() {
        quote! {}
    } else {
        quote! {
        lazy_static::lazy_static! {
            #( #statics )*
            }
        }
    };

    quote! {
        use retina_core::filter::actions::*;
        // Import potentially-needed traits
        use retina_core::subscription::{Trackable, Subscribable};
        use retina_datatypes::{FromSession, Tracked, FromMbuf, StaticData, PacketList};

        #subscribable

        #tracked

        #lazy_statics

        pub fn filter() -> retina_core::filter::FilterFactory<TrackedWrapper> {

            fn packet_continue(mbuf: &retina_core::Mbuf,
                               core_id: &retina_core::CoreId) -> Actions {
                #packet_continue
            }

            fn packet_filter(mbuf: &retina_core::Mbuf, tracked: &TrackedWrapper) -> Actions {
                #packet_filter
            }

            fn protocol_filter(conn: &retina_core::protocols::ConnData,
                               tracked: &TrackedWrapper) -> Actions {
                #proto_filter
            }

            fn session_filter(session: &retina_core::protocols::Session,
                              conn: &retina_core::protocols::ConnData,
                              tracked: &TrackedWrapper) -> Actions
            {
                #session_filter
            }

            fn packet_deliver(mbuf: &retina_core::Mbuf,
                              conn: &retina_core::protocols::ConnData,
                              tracked: &TrackedWrapper)
            {
                #packet_deliver_filter
            }

            fn connection_deliver(conn: &retina_core::protocols::ConnData,
                                  tracked: &TrackedWrapper)
            {
                #conn_deliver_filter
            }

            retina_core::filter::FilterFactory::new(
                #filter_str,
                packet_continue,
                packet_filter,
                protocol_filter,
                session_filter,
                packet_deliver,
                connection_deliver,
            )
        }

        #input

    }
    .into()
}

/// Generate a Retina program from a specification file.
/// This expects an input TOML file with the subscription specifications.
#[proc_macro_attribute]
pub fn subscription(args: TokenStream, input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as syn::ItemFn);
    let inp_file = parse_macro_input!(args as syn::LitStr).value();
    let config = SubscriptionConfig::from_file(&inp_file);
    generate(input, config)
}

/// Generate a Retina program without a specification file.
/// This expects a #[filter("...")] macro followed by the expected callback.
/// It must be used with #[retina_main(X)], where X = number of subscriptions.
#[proc_macro_attribute]
pub fn filter(args: TokenStream, input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as syn::ItemFn);
    let filter_str = parse_macro_input!(args as syn::LitStr).value();
    let (datatypes, callback) = parse_input(&input);
    println!(
        "Filter: {}, Datatypes: {:?}, Callback: {:?}",
        filter_str, datatypes, callback
    );

    // If more subscriptions to parse, just output the callback
    add_subscription(callback, datatypes, filter_str);
    if !is_done() {
        return quote! {
            #input
        }
        .into();
    }

    // Otherwise, ready to assemble
    let config = SubscriptionConfig::from_raw(&CACHED_SUBSCRIPTIONS.lock().unwrap());

    generate(input, config)
}

/// For generating a Retina program without a specification file
/// This expects to receive the number of subscriptions
#[proc_macro_attribute]
pub fn retina_main(args: TokenStream, input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as syn::ItemFn);
    let count = usize::from_str(parse_macro_input!(args as syn::LitInt).base10_digits()).unwrap();
    println!("Expecting {} subsctription(s)", count);
    set_count(count);

    // More subscriptions expected
    if !is_done() {
        return quote! {
            #input
        }
        .into();
    }

    // Otherwise, ready to assemble
    let config = SubscriptionConfig::from_raw(&CACHED_SUBSCRIPTIONS.lock().unwrap());

    generate(input, config)
}
