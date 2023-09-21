use heck::CamelCase;
use proc_macro2::{Ident, Span};
use quote::quote;

use retina_core::filter::ast::*;
use retina_core::filter::ptree::{PNode, PTree};

use crate::util::{binary_to_tokens, terminal_match};

pub(crate) fn gen_session_filter(
    ptree: &PTree,
    statics: &mut Vec<proc_macro2::TokenStream>,
    ct_nodes: Vec<usize>,
) -> proc_macro2::TokenStream {

    let mut body: Vec<proc_macro2::TokenStream> = vec![];
    let session_subtrees = ct_nodes
        .into_iter()
        .map(|id| ptree.get_subtree(id).unwrap())
        .collect::<Vec<_>>();

    for node in session_subtrees.iter() {
        add_node_match_arm(&mut body, statics, node);
    }

    let mut branches = quote! {};
    if !body.is_empty() {
        branches = {
            quote! {
                for node in &conn_results.nonterminal_nodes {
                    // TODO better to use nonterm bitmap to loop?
                    if *node == std::usize::MAX { continue; }
                    match node {
                        #( #body )*
                        _ => {}
                    }
                }
            }
        };
    }

    quote! {
        let mut result = retina_core::filter::FilterResultData::new();
        #branches
        result
    }
}

fn add_node_match_arm(
    code: &mut Vec<proc_macro2::TokenStream>,
    statics: &mut Vec<proc_macro2::TokenStream>,
    node: &PNode,
) {

    let idx_lit = syn::LitInt::new(&node.id.to_string(), Span::call_site());
    let mut body: Vec<proc_macro2::TokenStream> = vec![];
    gen_session_filter_util(&mut body, statics, node);
    let service = node.pred.get_protocol().name();
    let proto_name = Ident::new(service, Span::call_site());
    let proto_variant = Ident::new(&service.to_camel_case(), Span::call_site());

    if !body.is_empty() {
        code.push(quote! {
            #idx_lit => {
                if let retina_core::protocols::stream::SessionData::#proto_variant(#proto_name) = &session.data {
                    #( #body )*
                }

            }
        });
    }        
}


fn gen_session_filter_util(
    code: &mut Vec<proc_macro2::TokenStream>,
    statics: &mut Vec<proc_macro2::TokenStream>,
    node: &PNode,
) {
    for child in node.children.iter() {
        assert!(node.pred.on_connection() || node.pred.on_session());
        match &child.pred {
            Predicate::Unary { .. } => {
                panic!("Found unary predicate in session filter pattern");
            }
            Predicate::Binary {
                protocol,
                field,
                op,
                value,
            } => {
                assert!(protocol.name() == node.pred.get_protocol().name());
                add_binary_pred(code, statics, child, protocol, field, op, value);
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn add_binary_pred(
    code: &mut Vec<proc_macro2::TokenStream>,
    statics: &mut Vec<proc_macro2::TokenStream>,
    node: &PNode,
    protocol: &ProtocolName,
    field: &FieldName,
    op: &BinOp,
    value: &Value,
) {
    let mut body: Vec<proc_macro2::TokenStream> = vec![];
    gen_session_filter_util(&mut body, statics, node);
    let (terminal_code, terminal_bitmask) = terminal_match(node);
    if terminal_bitmask != 0 {
        body.push(terminal_code);
    }

    if !body.is_empty() {
        let pred_tokenstream = binary_to_tokens(protocol, field, op, value, statics);
        code.push(quote! {
            if #pred_tokenstream {
                #( #body )*
            }
        });
    }
}
