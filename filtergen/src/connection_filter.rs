use heck::CamelCase;
use proc_macro2::{Ident, Span};
use quote::quote;

use retina_core::filter::ast::*;
use retina_core::filter::ptree::{PNode, PTree, Terminate};

pub(crate) fn gen_connection_filter(
    ptree: &PTree,
    statics: &mut Vec<proc_macro2::TokenStream>,
    pt_nodes: Vec<usize>,
) -> (proc_macro2::TokenStream, Vec<usize>) {

    let mut ct_nodes = vec![];
    let mut body: Vec<proc_macro2::TokenStream> = vec![];
    let conn_subtrees = pt_nodes
        .into_iter()
        .map(|id| ptree.get_subtree(id).unwrap())
        .collect::<Vec<_>>();

    for node in conn_subtrees.iter() {
        add_node_match_arm(&mut ct_nodes, &mut body, statics, node);
    }

    let mut branches = quote! {};
    if !body.is_empty() {
        branches = {
            quote! {
                for node in &pkt_results.nonterminal_nodes {
                    if *node == std::usize::MAX { continue; }
                    match node {
                        #( #body )*
                        _ => {}
                    }
                }
            }
        };
    }

    let connection_filter = quote! {
        let mut result = retina_core::filter::FilterResultData::new();
        #branches
        result
    };
    (connection_filter, ct_nodes)
}

fn add_node_match_arm(
    ct_nodes: &mut Vec<usize>,
    code: &mut Vec<proc_macro2::TokenStream>,
    statics: &mut Vec<proc_macro2::TokenStream>,
    node: &PNode,
) {
    let idx_lit = syn::LitInt::new(&node.id.to_string(), Span::call_site());
    if node.is_terminal {
        ct_nodes.push(node.id);
        // If there is no connection node, return a match with the last idx of the matched
        // packet predicate node.
        code.push(quote! {
            #idx_lit => { 
                result.terminal_matches |= 0b1 << 0;
            }
        })
    } else {
        assert!(matches!(node.terminates, Terminate::Packet));
        let mut body: Vec<proc_macro2::TokenStream> = vec![];
        for child in node.children.iter().filter(|n| n.pred.on_connection()) {
            match &child.pred {
                Predicate::Unary { protocol } => {
                    add_service_pred(ct_nodes, &mut body, statics, child, protocol);
                }
                Predicate::Binary { .. } => {
                    panic!("Found binary predicate following a packet terminal node");
                }
            }
        }

        code.push(quote! {
            #idx_lit => {
                #( #body )*
            }
        })
    }
}

#[allow(clippy::ptr_arg)]
fn add_service_pred(
    ct_nodes: &mut Vec<usize>,
    code: &mut Vec<proc_macro2::TokenStream>,
    _statics: &mut Vec<proc_macro2::TokenStream>,
    node: &PNode,
    protocol: &ProtocolName,
) {
    if matches!(node.terminates, Terminate::Connection) {
        let service_ident = Ident::new(&protocol.name().to_camel_case(), Span::call_site());
        // let service_lit = syn::LitStr::new(&protocol.name().to_string(), Span::call_site());
        ct_nodes.push(node.id);
        let idx_lit = syn::LitInt::new(&node.id.to_string(), Span::call_site());

        if node.is_terminal {
            code.push(quote! {
                if matches!(conn.service(), retina_core::protocols::stream::ConnParser::#service_ident { .. }) {
                    result.terminal_matches |= 0b1 << 0; 
                }
            })
        } else {
            code.push(quote! {
                if matches!(conn.service(), retina_core::protocols::stream::ConnParser::#service_ident { .. }) {
                    result.nonterminal_matches |= 0b1 << 0;
                    result.nonterminal_nodes[0] = #idx_lit;
                }
            })
        }
    } else {
        panic!("Connection sub-filter does not terminate on a unary service predicate.")
    }
}
