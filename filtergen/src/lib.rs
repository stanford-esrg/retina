#![allow(clippy::needless_doctest_main)]
//! A macro for defining filters in Retina.
//!
//! [`filter`](macro@self::filter) is an attribute macro that parses a user-defined filter
//! expression to generate sub-filters that are statically inlined at each processing layer. This
//! verifies filter expressions at compile time and avoids overheads associated with interpreting
//! filters at runtime.
//!
//! # Usage
//! ```rust
//! use retina_core::config::default_config;
//! use retina_core::Runtime;
//! use retina_core::subscription::Connection;
//! use retina_filtergen::filter;
//!
//! #[filter("(ipv4 and tcp.port >= 100 and tls.sni ~ 'netflix') or http")]
//! fn main() {
//!    let cfg = default_config();
//!    let callback = |conn: Connection| {
//!        println!("{:#?}", conn);
//!    };
//!    let mut runtime = Runtime::new(cfg, filter, callback).unwrap();
//!    runtime.run();
//! }
//! ```
//!
//! # Syntax
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

mod connection_filter;
mod packet_filter;
mod session_filter;
mod util;

use proc_macro::TokenStream;
use quote::quote;
use syn::parse_macro_input;

use retina_core::filter::Filter;

use crate::connection_filter::gen_connection_filter;
use crate::packet_filter::gen_packet_filter;
use crate::session_filter::gen_session_filter;

/// Macro for generating filters.
///
/// ## Examples
/// ```
/// #[filter("")] // no filter
/// fn main() {}
/// ```
///
/// ```
/// #[filter("tcp.port = 80")]
/// fn main() {}
/// ```
///
/// ```
/// #[filter("http.method = 'GET'")]
/// fn main() {}
/// ```
///
/// ```
/// #[filter("(ipv4 and tcp.port >= 100 and tls.sni ~ 'netflix') or http")]
/// fn main() {}
/// ```
#[proc_macro_attribute]
pub fn filter(args: TokenStream, input: TokenStream) -> TokenStream {
    let filter_str = parse_macro_input!(args as syn::LitStr).value();
    let input = parse_macro_input!(input as syn::ItemFn);
    // let input_sig = &input.sig.ident;

    let filter = Filter::from_str(&filter_str, false).unwrap();

    let mut ptree = filter.to_ptree();
    ptree.prune_branches();
    // Displays the predicate trie during compilation.
    println!("{}", ptree);

    // store lazily evaluated statics like pre-compiled Regex
    let mut statics: Vec<proc_macro2::TokenStream> = vec![];

    let (packet_filter_body, pt_nodes) = gen_packet_filter(&ptree, &mut statics);
    let (connection_filter_body, ct_nodes) = gen_connection_filter(&ptree, &mut statics, pt_nodes);
    let session_filter_body = gen_session_filter(&ptree, &mut statics, ct_nodes);

    let lazy_statics = if statics.is_empty() {
        quote! {}
    } else {
        quote! {
            lazy_static::lazy_static! {
                #( #statics )*
            }
        }
    };

    let packet_filter_fn = quote! {
        #[inline]
        fn packet_filter(mbuf: &retina_core::Mbuf) -> retina_core::filter::FilterResult {
            #packet_filter_body
        }
    };

    let connection_filter_fn = quote! {
        #[inline]
        fn connection_filter(conn: &retina_core::protocols::stream::ConnData) -> retina_core::filter::FilterResult {
            #connection_filter_body
        }
    };

    let session_filter_fn = quote! {
        #[inline]
        fn session_filter(session: &retina_core::protocols::stream::Session, idx: usize) -> bool {
            #session_filter_body
        }
    };

    let filtergen = quote! {
        fn filter() -> retina_core::filter::FilterFactory {
            #packet_filter_fn
            #connection_filter_fn
            #session_filter_fn
            retina_core::filter::FilterFactory::new(#filter_str, packet_filter, connection_filter, session_filter)
        }

        #lazy_statics
        #input

    };
    filtergen.into()
}
