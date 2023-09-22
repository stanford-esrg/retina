Collapsed Filter:
`- ethernet (0) : 
   |- ipv4 (1) p:  0*
   `- ipv6 (2) : 
      `- tcp (3) p:  0
         |- http (4) c:  0*
         `- tls (5) c:  0
            `- tls.sni matches ^.*\.com$ (6) s:  0*

Complete Filter:
`- ethernet (0) : 
   |- ipv4 (1) p:  1*
   |  `- tcp (2) p:  0
   |     `- tls (3) c:  0
   |        `- tls.sni matches ^.*\.com$ (4) s:  0*
   `- ipv6 (5) : 
      `- tcp (6) p:  0 1
         |- tls (7) c:  0
         |  `- tls.sni matches ^.*\.com$ (8) s:  0*
         `- http (9) c:  1*

Protocols for parsers:
http or tls
#![feature(prelude_import)]
#[prelude_import]
use std::prelude::rust_2021::*;
#[macro_use]
extern crate std;
use retina_core::config::default_config;
use retina_core::subscription::{SubscribableEnum, SubscribableWrapper};
use retina_core::Runtime;
use retina_filtergen::filter;
fn filter() -> retina_core::filter::FilterFactory {
    #[inline]
    fn packet_filter(mbuf: &retina_core::Mbuf) -> retina_core::filter::FilterResultData {
        let mut result = retina_core::filter::FilterResultData::new();
        if let Ok(ethernet)
            = &retina_core::protocols::packet::Packet::parse_to::<
                retina_core::protocols::packet::ethernet::Ethernet,
            >(mbuf) {
            if let Ok(ipv4)
                = &retina_core::protocols::packet::Packet::parse_to::<
                    retina_core::protocols::packet::ipv4::Ipv4,
                >(ethernet) {
                if let Ok(tcp)
                    = &retina_core::protocols::packet::Packet::parse_to::<
                        retina_core::protocols::packet::tcp::Tcp,
                    >(ipv4) {
                    result.nonterminal_matches |= 1;
                    result.nonterminal_nodes[0] = 2;
                }
                result.terminal_matches |= 2;
            } else if let Ok(ipv6)
                = &retina_core::protocols::packet::Packet::parse_to::<
                    retina_core::protocols::packet::ipv6::Ipv6,
                >(ethernet) {
                if let Ok(tcp)
                    = &retina_core::protocols::packet::Packet::parse_to::<
                        retina_core::protocols::packet::tcp::Tcp,
                    >(ipv6) {
                    result.nonterminal_matches |= 3;
                    result.nonterminal_nodes[0] = 6;
                    result.nonterminal_nodes[1] = 6;
                }
            }
        }
        return result;
    }
    #[inline]
    fn connection_filter(
        pkt_results: &retina_core::filter::FilterResultData,
        conn: &retina_core::protocols::stream::ConnData,
    ) -> retina_core::filter::FilterResultData {
        let mut result = retina_core::filter::FilterResultData::new();
        for node in &pkt_results.nonterminal_nodes {
            if *node == std::usize::MAX {
                continue;
            }
            match node {
                2 => {
                    if match conn.service() {
                        retina_core::protocols::stream::ConnParser::Tls { .. } => true,
                        _ => false,
                    } {
                        result.nonterminal_matches |= 1;
                        result.nonterminal_nodes[0] = 3;
                    }
                }
                6 => {
                    if match conn.service() {
                        retina_core::protocols::stream::ConnParser::Tls { .. } => true,
                        _ => false,
                    } {
                        result.nonterminal_matches |= 1;
                        result.nonterminal_nodes[0] = 7;
                    }
                    if match conn.service() {
                        retina_core::protocols::stream::ConnParser::Http { .. } => true,
                        _ => false,
                    } {
                        result.terminal_matches |= 2;
                    }
                }
                _ => {}
            }
        }
        result
    }
    #[inline]
    fn session_filter(
        session: &retina_core::protocols::stream::Session,
        conn_results: &retina_core::filter::FilterResultData,
    ) -> retina_core::filter::FilterResultData {
        let mut result = retina_core::filter::FilterResultData::new();
        for node in &conn_results.nonterminal_nodes {
            if *node == std::usize::MAX {
                continue;
            }
            match node {
                3 => {
                    if let retina_core::protocols::stream::SessionData::Tls(tls)
                        = &session.data
                    {
                        if RE0.is_match(&tls.sni()[..]) {
                            result.terminal_matches |= 1;
                        }
                    }
                }
                7 => {
                    if let retina_core::protocols::stream::SessionData::Tls(tls)
                        = &session.data
                    {
                        if RE1.is_match(&tls.sni()[..]) {
                            result.terminal_matches |= 1;
                        }
                    }
                }
                _ => {}
            }
        }
        result
    }
    retina_core::filter::FilterFactory::new(
        "(tls.sni ~ '^.*\\.com$') or (ipv4 or http)",
        "http or tls",
        packet_filter,
        connection_filter,
        session_filter,
    )
}
#[allow(missing_copy_implementations)]
#[allow(non_camel_case_types)]
#[allow(dead_code)]
struct RE0 {
    __private_field: (),
}
#[doc(hidden)]
static RE0: RE0 = RE0 { __private_field: () };
impl ::lazy_static::__Deref for RE0 {
    type Target = regex::Regex;
    fn deref(&self) -> &regex::Regex {
        #[inline(always)]
        fn __static_ref_initialize() -> regex::Regex {
            regex::Regex::new("^.*\\.com$").unwrap()
        }
        #[inline(always)]
        fn __stability() -> &'static regex::Regex {
            static LAZY: ::lazy_static::lazy::Lazy<regex::Regex> = ::lazy_static::lazy::Lazy::INIT;
            LAZY.get(__static_ref_initialize)
        }
        __stability()
    }
}
impl ::lazy_static::LazyStatic for RE0 {
    fn initialize(lazy: &Self) {
        let _ = &**lazy;
    }
}
#[allow(missing_copy_implementations)]
#[allow(non_camel_case_types)]
#[allow(dead_code)]
struct RE1 {
    __private_field: (),
}
#[doc(hidden)]
static RE1: RE1 = RE1 { __private_field: () };
impl ::lazy_static::__Deref for RE1 {
    type Target = regex::Regex;
    fn deref(&self) -> &regex::Regex {
        #[inline(always)]
        fn __static_ref_initialize() -> regex::Regex {
            regex::Regex::new("^.*\\.com$").unwrap()
        }
        #[inline(always)]
        fn __stability() -> &'static regex::Regex {
            static LAZY: ::lazy_static::lazy::Lazy<regex::Regex> = ::lazy_static::lazy::Lazy::INIT;
            LAZY.get(__static_ref_initialize)
        }
        __stability()
    }
}
impl ::lazy_static::LazyStatic for RE1 {
    fn initialize(lazy: &Self) {
        let _ = &**lazy;
    }
}
fn main() {
    let cfg = default_config();
    let callback = |tls: SubscribableEnum| {
        {
            ::std::io::_print(format_args!("CB 1: {0:?}\n", tls));
        };
    };
    let callback2 = |http: SubscribableEnum| {
        {
            ::std::io::_print(format_args!("CB 2: {0:?}\n", http));
        };
    };
    let mut runtime: Runtime<SubscribableWrapper> = Runtime::new(
            cfg,
            filter,
            <[_]>::into_vec(
                #[rustc_box]
                ::alloc::boxed::Box::new([Box::new(callback), Box::new(callback2)]),
            ),
        )
        .unwrap();
    runtime.run();
}
