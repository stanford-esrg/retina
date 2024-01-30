use heck::CamelCase;
use proc_macro2::{Ident, Span};
use quote::quote;

use retina_core::filter::ast::*;
use retina_core::filter::ptree::{PNode, PTree};
use retina_core::protocol;
use crate::utils::*;


pub(crate) fn gen_packet_filter(
    ptree: &PTree,
    statics: &mut Vec<proc_macro2::TokenStream>,
    deliver: bool
) -> proc_macro2::TokenStream {

    let name = "ethernet";
    let outer = Ident::new(name, Span::call_site());
    let outer_type = Ident::new(&outer.to_string().to_camel_case(), Span::call_site());

    let mut body: Vec<proc_macro2::TokenStream> = vec![];

    gen_packet_filter_util(
        &mut body,
        statics,
        &ptree.root,
        &protocol!("frame"),
    );

    let mut branches = quote! {};
    if !body.is_empty() {
        branches = {
            quote! {
                if let Ok(#outer) = &retina_core::protocols::packet::Packet::parse_to::<retina_core::protocols::packet::#outer::#outer_type>(mbuf) {
                    #( #body )*
                }
            }
        };
    }

    let mut start = quote! {};
    let mut ret = quote! {};
    if !deliver {
        start = quote! { let mut result = retina_core::filter::Actions::new(); };
        ret = quote! { result };
    }

    let packet_filter = quote! {
        #start
        #branches
        #ret
    };
    packet_filter
}

fn gen_packet_filter_util(
    code: &mut Vec<proc_macro2::TokenStream>,
    statics: &mut Vec<proc_macro2::TokenStream>,
    node: &PNode,
    outer_protocol: &ProtocolName,
) {
    let mut first_unary = true;
    for child in node.children.iter().filter(|n| n.pred.on_packet()) {
        match &child.pred {
            Predicate::Unary { protocol } => {
                add_unary_pred(
                    code,
                    statics,
                    child,
                    node.pred.get_protocol(),
                    protocol,
                    first_unary,
                );
                first_unary = false;
            }
            Predicate::Binary {
                protocol,
                field,
                op,
                value,
            } => {
                add_binary_pred(
                    code,
                    statics,
                    child,
                    outer_protocol,
                    protocol,
                    field,
                    op,
                    value,
                );
            }
        }
    }
}

fn add_unary_pred(
    code: &mut Vec<proc_macro2::TokenStream>,
    statics: &mut Vec<proc_macro2::TokenStream>,
    node: &PNode,
    outer_protocol: &ProtocolName,
    protocol: &ProtocolName,
    first_unary: bool,
) {
    let outer = Ident::new(outer_protocol.name(), Span::call_site());
    let ident = Ident::new(protocol.name(), Span::call_site());
    let ident_type = Ident::new(&ident.to_string().to_camel_case(), Span::call_site());

    let mut body: Vec<proc_macro2::TokenStream> = vec![];
    gen_packet_filter_util(&mut body, statics, node, outer_protocol);
    update_body(&mut body, node);

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
fn add_binary_pred(
    code: &mut Vec<proc_macro2::TokenStream>,
    statics: &mut Vec<proc_macro2::TokenStream>,
    node: &PNode,
    outer_protocol: &ProtocolName,
    protocol: &ProtocolName,
    field: &FieldName,
    op: &BinOp,
    value: &Value,
) {
    let mut body: Vec<proc_macro2::TokenStream> = vec![];
    gen_packet_filter_util(&mut body, statics, node, outer_protocol);
    update_body(&mut body, node);

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