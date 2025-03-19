use retina_core::filter::ast::{BinOp, FieldName, ProtocolName, Value};
use retina_core::filter::ptree::{FilterLayer, PNode};
use retina_core::filter::{Level, SubscriptionSpec};

use crate::data::{build_callback, build_packet_callback};
use heck::CamelCase;
use proc_macro2::{Ident, Span};
use quote::quote;
use regex::{bytes::Regex as BytesRegex, Regex};
use std::collections::HashMap;
use std::sync::Mutex;

lazy_static! {
    pub(crate) static ref DELIVER: Mutex<HashMap<usize, SubscriptionSpec>> =
        Mutex::new(HashMap::new());
}

pub(crate) fn binary_to_tokens(
    protocol: &ProtocolName,
    field: &FieldName,
    op: &BinOp,
    value: &Value,
    statics: &mut Vec<proc_macro2::TokenStream>,
) -> proc_macro2::TokenStream {
    assert!(!field.is_combined()); // should have been split when building tree
    let proto = Ident::new(protocol.name(), Span::call_site());
    let field = Ident::new(field.name(), Span::call_site());

    match value {
        Value::Int(val) => {
            let val_lit = syn::LitInt::new(&val.to_string(), Span::call_site());
            match *op {
                BinOp::Eq => quote! { #proto.#field() == #val_lit },
                BinOp::Ne => quote! { #proto.#field() != #val_lit },
                BinOp::Ge => quote! { #proto.#field() >= #val_lit },
                BinOp::Le => quote! { #proto.#field() <= #val_lit },
                BinOp::Gt => quote! { #proto.#field() > #val_lit },
                BinOp::Lt => quote! { #proto.#field() < #val_lit },
                _ => panic!("Invalid binary operation `{}` for value: `{}`.", op, value),
            }
        }
        Value::IntRange { from, to } => {
            let from_lit = syn::LitInt::new(&from.to_string(), Span::call_site());
            let to_lit = syn::LitInt::new(&to.to_string(), Span::call_site());
            match *op {
                BinOp::In => quote! {
                    #proto.#field() >= #from_lit && #proto.#field() <= #to_lit
                },
                _ => panic!("Invalid binary operation `{}` for value: `{}`.", op, value),
            }
        }
        Value::Ipv4(ipv4net) => {
            let addr_u32 = u32::from(ipv4net.addr());
            let addr_lit = syn::LitInt::new(&addr_u32.to_string(), Span::call_site());

            let netmask_u32 = u32::from(ipv4net.netmask());
            let netmask_lit = syn::LitInt::new(&netmask_u32.to_string(), Span::call_site());

            let net_u32 = addr_u32 & netmask_u32;
            let net_lit = syn::LitInt::new(&net_u32.to_string(), Span::call_site());

            match *op {
                BinOp::Eq => {
                    if ipv4net.prefix_len() == 32 {
                        quote! { u32::from(#proto.#field()) == #addr_lit }
                    } else {
                        quote! { u32::from(#proto.#field()) & #netmask_lit == #net_lit }
                    }
                }
                BinOp::Ne => {
                    if ipv4net.prefix_len() == 32 {
                        quote! { u32::from(#proto.#field()) != #addr_lit }
                    } else {
                        quote! { u32::from(#proto.#field()) & #netmask_lit != #net_lit }
                    }
                }
                BinOp::In => {
                    if ipv4net.prefix_len() == 32 {
                        quote! { u32::from(#proto.#field()) == #addr_lit }
                    } else {
                        quote! { u32::from(#proto.#field()) & #netmask_lit == #net_lit }
                    }
                }
                _ => panic!("Invalid binary operation `{}` for value: `{}`.", op, value),
            }
        }
        Value::Ipv6(ipv6net) => {
            let addr_u128 = u128::from(ipv6net.addr());
            let addr_lit = syn::LitInt::new(&addr_u128.to_string(), Span::call_site());

            let netmask_u128 = u128::from(ipv6net.netmask());
            let netmask_lit = syn::LitInt::new(&netmask_u128.to_string(), Span::call_site());

            let net_u128 = addr_u128 & netmask_u128;
            let net_lit = syn::LitInt::new(&net_u128.to_string(), Span::call_site());

            match *op {
                BinOp::Eq => {
                    if ipv6net.prefix_len() == 128 {
                        quote! { u128::from(#proto.#field()) == #addr_lit }
                    } else {
                        quote! { u128::from(#proto.#field()) & #netmask_lit == #net_lit }
                    }
                }
                BinOp::Ne => {
                    if ipv6net.prefix_len() == 128 {
                        quote! { u128::from(#proto.#field()) != #addr_lit }
                    } else {
                        quote! { u128::from(#proto.#field()) & #netmask_lit != #net_lit }
                    }
                }
                BinOp::In => {
                    if ipv6net.prefix_len() == 128 {
                        quote! { u128::from(#proto.#field()) == #addr_lit }
                    } else {
                        quote! { u128::from(#proto.#field()) & #netmask_lit == #net_lit }
                    }
                }
                _ => panic!("Invalid binary operation `{}` for value: `{}`.", op, value),
            }
        }
        Value::Text(text) => {
            match *op {
                BinOp::Eq => {
                    let val_lit = syn::LitStr::new(text, Span::call_site());
                    quote! { #proto.#field() == #val_lit }
                }
                BinOp::Ne => {
                    let val_lit = syn::LitStr::new(text, Span::call_site());
                    quote! { #proto.#field() != #val_lit }
                }
                BinOp::En => {
                    let field_ident =
                        Ident::new(&field.to_string().to_camel_case(), Span::call_site());
                    let variant_ident =
                        Ident::new(&text.as_str().to_camel_case(), Span::call_site());
                    quote! { #proto.#field() == retina_core::protocols::stream::#proto::#field_ident::#variant_ident }
                }
                BinOp::Re => {
                    let val_lit = syn::LitStr::new(text, Span::call_site());
                    if Regex::new(text).is_err() {
                        panic!("Invalid Regex string")
                    }

                    let re_name = format!("RE{}", statics.len());
                    let re_ident = Ident::new(&re_name, Span::call_site());
                    let lazy_re = quote! {
                        static ref #re_ident: regex::Regex = regex::Regex::new(#val_lit).unwrap();
                    };
                    // avoids compiling the Regex every time
                    statics.push(lazy_re);
                    quote! {
                        #re_ident.is_match(&#proto.#field()[..])
                    }
                    // quote! {
                    //     Regex::new(#val_lit).unwrap().is_match(#proto.#field())
                    // }
                }
                BinOp::ByteRe => {
                    let val_lit = syn::LitStr::new(text, Span::call_site());
                    if BytesRegex::new(text).is_err() {
                        panic!("Invalid Regex string")
                    }

                    let re_name = format!("RE{}", statics.len());
                    let re_ident = Ident::new(&re_name, Span::call_site());

                    let lazy_re = quote! {
                        static ref #re_ident: regex::bytes::Regex = regex::bytes::Regex::new(#val_lit).unwrap();
                    };
                    // avoids compiling the Regex every time
                    statics.push(lazy_re);

                    quote! {
                        #re_ident.is_match((&#proto.#field()).as_ref())
                    }
                }
                BinOp::Contains => {
                    let val_lit = syn::LitStr::new(text, Span::call_site());

                    let finder_name = format!("FINDER{}", statics.len());
                    let finder_ident = Ident::new(&finder_name, Span::call_site());
                    let lazy_finder = quote! {
                        static ref #finder_ident: memchr::memmem::Finder<'static> = memchr::memmem::Finder::new(#val_lit.as_bytes());
                    };
                    statics.push(lazy_finder);
                    quote! {
                        #finder_ident.find(#proto.#field().as_bytes()).is_some()
                    }
                }
                BinOp::NotContains => {
                    let val_lit = syn::LitStr::new(text, Span::call_site());

                    let finder_name = format!("FINDER{}", statics.len());
                    let finder_ident = Ident::new(&finder_name, Span::call_site());
                    let lazy_finder = quote! {
                        static ref #finder_ident: memchr::memmem::Finder<'static> = memchr::memmem::Finder::new(#val_lit.as_bytes());
                    };
                    statics.push(lazy_finder);
                    quote! {
                        #finder_ident.find(#proto.#field().as_bytes()).is_none()
                    }
                }
                _ => panic!("Invalid binary operation `{}` for value: `{}`.", op, value),
            }
        }
        Value::Byte(b) => match *op {
            BinOp::Eq => {
                let bytes_lit = syn::LitByteStr::new(b, Span::call_site());
                quote! {
                    #proto.#field().as_ref() as &[u8] == #bytes_lit
                }
            }
            BinOp::Ne => {
                let bytes_lit = syn::LitByteStr::new(b, Span::call_site());
                quote! {
                    #proto.#field().as_ref() as &[u8] != #bytes_lit
                }
            }
            BinOp::Contains => {
                let bytes_lit = syn::LitByteStr::new(b, Span::call_site());

                let finder_name = format!("FINDER{}", statics.len());
                let finder_ident = Ident::new(&finder_name, Span::call_site());
                let lazy_finder = quote! {
                    static ref #finder_ident: memchr::memmem::Finder<'static> = memchr::memmem::Finder::new(#bytes_lit);
                };
                statics.push(lazy_finder);
                quote! {
                    #finder_ident.find(#proto.#field().as_ref()).is_some()
                }
            }
            BinOp::NotContains => {
                let bytes_lit = syn::LitByteStr::new(b, Span::call_site());

                let finder_name = format!("FINDER{}", statics.len());
                let finder_ident = Ident::new(&finder_name, Span::call_site());
                let lazy_finder = quote! {
                    static ref #finder_ident: memchr::memmem::Finder<'static> = memchr::memmem::Finder::new(#bytes_lit);
                };
                statics.push(lazy_finder);
                quote! {
                    #finder_ident.find(#proto.#field().as_ref()).is_none()
                }
            }
            _ => panic!("Invalid binary operation `{}` for value: `{}`.", op, value),
        },
    }
}

pub(crate) fn update_body(
    body: &mut Vec<proc_macro2::TokenStream>,
    node: &PNode,
    filter_layer: FilterLayer,
    session_loop: bool,
) {
    if !node.actions.drop() {
        let actions = node.actions.clone();
        body.push(quote! { result.push(&#actions); });
    }
    if !node.deliver.is_empty() {
        for d in &node.deliver {
            let id = &d.id;
            {
                let lock = DELIVER.lock().unwrap();
                let spec = lock
                    .get(id)
                    .unwrap_or_else(|| panic!("Cannot find ID {}", id));

                if matches!(spec.level, Level::Packet) {
                    body.push(build_packet_callback(spec, filter_layer));
                } else {
                    body.push(build_callback(spec, filter_layer, session_loop));
                }
            }
        }
    }
}

pub(crate) type BuildChildNodesFn = dyn Fn(
    &mut Vec<proc_macro2::TokenStream>,
    &mut Vec<proc_macro2::TokenStream>,
    &PNode,
    FilterLayer,
);

pub(crate) struct PacketDataFilter;

impl PacketDataFilter {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn add_unary_pred(
        code: &mut Vec<proc_macro2::TokenStream>,
        statics: &mut Vec<proc_macro2::TokenStream>,
        node: &PNode,
        outer_protocol: &ProtocolName,
        protocol: &ProtocolName,
        first_unary: bool,
        filter_layer: FilterLayer,
        build_child_nodes: &BuildChildNodesFn,
    ) {
        let outer = Ident::new(outer_protocol.name(), Span::call_site());
        let ident = Ident::new(protocol.name(), Span::call_site());
        let ident_type = Ident::new(&ident.to_string().to_camel_case(), Span::call_site());

        let mut body: Vec<proc_macro2::TokenStream> = vec![];
        (build_child_nodes)(&mut body, statics, node, filter_layer);
        update_body(&mut body, node, filter_layer, false);

        if first_unary {
            code.push(quote! {
                if let Ok(#ident) = &retina_core::protocols::packet::Packet::parse_to::<retina_core::protocols::packet::#ident::#ident_type>(#outer) {
                    #( #body )*
                }
            });
        } else {
            code.push(quote! {
                else if let Ok(#ident) = &retina_core::protocols::packet::Packet::parse_to::<retina_core::protocols::packet::#ident::#ident_type>(#outer) {
                    #( #body )*
                }
            });
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn add_binary_pred(
        code: &mut Vec<proc_macro2::TokenStream>,
        statics: &mut Vec<proc_macro2::TokenStream>,
        node: &PNode,
        protocol: &ProtocolName,
        field: &FieldName,
        op: &BinOp,
        value: &Value,
        filter_layer: FilterLayer,
        build_child_nodes: &BuildChildNodesFn,
    ) {
        let mut body: Vec<proc_macro2::TokenStream> = vec![];
        (build_child_nodes)(&mut body, statics, node, filter_layer);
        update_body(&mut body, node, filter_layer, false);

        let pred_tokenstream = binary_to_tokens(protocol, field, op, value, statics);
        if node.if_else {
            code.push(quote! {
                else if #pred_tokenstream {
                    #( #body )*
                }
            });
        } else {
            code.push(quote! {
                if #pred_tokenstream {
                    #( #body )*
                }
            });
        }
    }

    pub(crate) fn add_root_pred(
        root: &PNode,
        body: &Vec<proc_macro2::TokenStream>,
    ) -> proc_macro2::TokenStream {
        let name = "ethernet";
        let outer = Ident::new(name, Span::call_site());
        let outer_type = Ident::new(&outer.to_string().to_camel_case(), Span::call_site());

        if !body.is_empty() && root.children.iter().any(|n| n.pred.on_packet()) {
            return quote! {
                if let Ok(#outer) = &retina_core::protocols::packet::Packet::parse_to::<retina_core::protocols::packet::#outer::#outer_type>(mbuf) {
                    #( #body )*
                }
            };
        }
        quote! { #( #body )* }
    }
}

// \note Because each stage's filter may be different, we default to applying an
//       end-to-end filter at each stage. This may require, for example, re-checking
//       IP addresses. This can/should be optimized in the future.
pub(crate) struct ConnDataFilter;

impl ConnDataFilter {
    pub(crate) fn add_unary_pred(
        code: &mut Vec<proc_macro2::TokenStream>,
        statics: &mut Vec<proc_macro2::TokenStream>,
        node: &PNode,
        protocol: &ProtocolName,
        first_unary: bool,
        filter_layer: FilterLayer,
        build_child_nodes: &BuildChildNodesFn,
    ) {
        let ident = Ident::new(protocol.name(), Span::call_site());
        let ident_type = Ident::new(
            &(protocol.name().to_owned().to_camel_case() + "CData"),
            Span::call_site(),
        );

        let mut body: Vec<proc_macro2::TokenStream> = vec![];
        (build_child_nodes)(&mut body, statics, node, filter_layer);
        update_body(&mut body, node, filter_layer, false);

        let condition = quote! {
            &retina_core::protocols::stream::ConnData::parse_to::<retina_core::protocols::stream::conn::#ident_type>(conn)
        };

        if first_unary {
            code.push(quote! {
                if let Ok(#ident) = #condition {
                    #( #body )*
                }
            });
        } else {
            code.push(quote! {
                else if let Ok(#ident) = #condition {
                    #( #body )*
                }
            });
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn add_binary_pred(
        code: &mut Vec<proc_macro2::TokenStream>,
        statics: &mut Vec<proc_macro2::TokenStream>,
        node: &PNode,
        protocol: &ProtocolName,
        field: &FieldName,
        op: &BinOp,
        value: &Value,
        filter_layer: FilterLayer,
        build_child_nodes: &BuildChildNodesFn,
    ) {
        let mut body: Vec<proc_macro2::TokenStream> = vec![];
        (build_child_nodes)(&mut body, statics, node, filter_layer);
        update_body(&mut body, node, filter_layer, false);

        let pred_tokenstream = binary_to_tokens(protocol, field, op, value, statics);
        if node.if_else {
            code.push(quote! {
                else if #pred_tokenstream {
                    #( #body )*
                }
            });
        } else {
            code.push(quote! {
                if #pred_tokenstream {
                    #( #body )*
                }
            });
        }
    }

    #[allow(clippy::ptr_arg)]
    pub(crate) fn add_service_pred(
        code: &mut Vec<proc_macro2::TokenStream>,
        statics: &mut Vec<proc_macro2::TokenStream>,
        node: &PNode,
        protocol: &ProtocolName,
        filter_layer: FilterLayer,
        build_child_nodes: &BuildChildNodesFn,
    ) {
        let service_ident = Ident::new(&protocol.name().to_camel_case(), Span::call_site());
        let mut body: Vec<proc_macro2::TokenStream> = vec![];
        (build_child_nodes)(&mut body, statics, node, filter_layer);
        update_body(&mut body, node, filter_layer, false);

        if node.if_else {
            code.push( quote! {
                else if matches!(conn.service(), retina_core::protocols::stream::ConnParser::#service_ident { .. }) {
                    #( #body )*
                }
            } );
        } else {
            code.push( quote! {
                if matches!(conn.service(), retina_core::protocols::stream::ConnParser::#service_ident { .. }) {
                    #( #body )*
                }
            } );
        }
    }
}

pub(crate) struct SessionDataFilter;

impl SessionDataFilter {
    #[allow(clippy::ptr_arg)]
    pub(crate) fn add_service_pred(
        code: &mut Vec<proc_macro2::TokenStream>,
        statics: &mut Vec<proc_macro2::TokenStream>,
        node: &PNode,
        protocol: &ProtocolName,
        first_unary: bool,
        filter_layer: FilterLayer,
        build_child_nodes: &BuildChildNodesFn,
    ) {
        let mut body: Vec<proc_macro2::TokenStream> = vec![];
        (build_child_nodes)(&mut body, statics, node, filter_layer);
        update_body(&mut body, node, filter_layer, false);

        let service = protocol.name();
        let proto_name = Ident::new(service, Span::call_site());
        let proto_variant = Ident::new(&service.to_camel_case(), Span::call_site());

        let condition = quote! { let retina_core::protocols::stream::SessionData::#proto_variant(#proto_name) = &session.data };
        if first_unary {
            code.push(quote! {
                if #condition {
                    #( #body )*
                }
            })
        } else {
            code.push(quote! {
                else if #condition {
                    #( #body )*
                }
            })
        }
    }
}
