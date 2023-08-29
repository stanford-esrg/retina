use heck::CamelCase;
use proc_macro2::{Ident, Span};
use quote::quote;

use retina_core::filter::ast::*;
use retina_core::filter::ptree::{PNode, PTree, Terminate};

use crate::util::binary_to_tokens;

pub(crate) fn gen_session_filter(
    ptree: &PTree,
    statics: &mut Vec<proc_macro2::TokenStream>,
    ct_nodes: Vec<usize>,
) -> proc_macro2::TokenStream {
    if ptree.root.is_terminal {
        // only ethernet - no filter specified
        return quote! {
            let mut result = retina_core::filter::FilterResultData::new(1);
            result.terminal_matches |= 0b1 << 0;
            result
        };
    }

    let mut body: Vec<proc_macro2::TokenStream> = vec![];
    let session_subtrees = ct_nodes
        .into_iter()
        .map(|id| ptree.get_subtree(id).unwrap())
        .collect::<Vec<_>>();

    for node in session_subtrees.iter() {
        add_node_match_arm(&mut body, statics, node);
    }

    quote! {
        let mut result = retina_core::filter::FilterResultData::new(1);
        for node in &conn_results.nonterminal_nodes {
            match node {
                #( #body )*
                _ => {}
            }
        }
        result
    }
}

fn add_node_match_arm(
    code: &mut Vec<proc_macro2::TokenStream>,
    statics: &mut Vec<proc_macro2::TokenStream>,
    node: &PNode,
) {
    let idx_lit = syn::LitInt::new(&node.id.to_string(), Span::call_site());
    if node.is_terminal {
        code.push(quote! {
            #idx_lit => { 
                result.terminal_matches |= 0b1 << 0; 
            }
        })
    } else {
        assert!(matches!(node.terminates, Terminate::Connection));
        let mut body: Vec<proc_macro2::TokenStream> = vec![];
        gen_session_filter_util(&mut body, statics, node);

        let service = node.pred.get_protocol().name();
        let proto_name = Ident::new(service, Span::call_site());
        let proto_variant = Ident::new(&service.to_camel_case(), Span::call_site());

        code.push(quote! {
            #idx_lit => {
                if let retina_core::protocols::stream::SessionData::#proto_variant(#proto_name) = &session.data {
                    #( #body )*
                }

            }
        })
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
    if node.is_terminal {
        // node terminates a session filter pattern
        body.push(quote! {
            result.terminal_matches |= 0b1 << 0;
        });
    }

    let pred_tokenstream = binary_to_tokens(protocol, field, op, value, statics);
    code.push(quote! {
        if #pred_tokenstream {
            #( #body )*
        }
    });
}
