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
            true
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
        match idx {
            #( #body )*
            _ => return false,
        }
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
            #idx_lit => return true,
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
                return false;

            }
        })
    }
}

// fn add_parser_match_arm(
//     code: &mut Vec<proc_macro2::TokenStream>,
//     statics: &mut Vec<proc_macro2::TokenStream>,
//     node: &PNode,
//     protocol: &ProtocolName,
// ) {
//     assert!(node.pred.is_unary());
//     assert!(node.pred.on_connection() || node.pred.on_session());

//     let ident = Ident::new(
//         &(protocol.name().to_owned() + "sessions"),
//         Span::call_site(),
//     );
//     let ident_type = Ident::new(&protocol.name().to_camel_case(), Span::call_site());

//     let mut body: Vec<proc_macro2::TokenStream> = vec![];
//     if node.is_terminal {
//         // node terminates a stream filter pattern
//         body.push(quote! {
//             return true;
//         });
//     } else {
//         add_conditional_filter(&mut body, statics, node);
//     }

//     code.push(quote! {
//         retina_core::protocols::stream::Parser::#ident_type(#ident) => {
//             #( #body )*
//         }
//     })
// }

// fn add_conditional_filter(
//     code: &mut Vec<proc_macro2::TokenStream>,
//     statics: &mut Vec<proc_macro2::TokenStream>,
//     node: &PNode,
// ) {
//     let mut body_filter_all: Vec<proc_macro2::TokenStream> = vec![];
//     let mut body_filter_back: Vec<proc_macro2::TokenStream> = vec![];

//     add_filter_match_arm(&mut body_filter_all, &mut body_filter_back, statics, node);
//     code.push(quote! {
//         if check_all {
//             #( #body_filter_all )*
//         } else {
//             #( #body_filter_back )*
//         }
//     })
// }

// fn add_filter_match_arm(
//     body_filter_all: &mut Vec<proc_macro2::TokenStream>,
//     body_filter_back: &mut Vec<proc_macro2::TokenStream>,
//     statics: &mut Vec<proc_macro2::TokenStream>,
//     node: &PNode,
// ) {
//     let ident = Ident::new(node.pred.get_protocol().name(), Span::call_site());
//     let ident_mixed = Ident::new(
//         &(node.pred.get_protocol().name().to_owned() + "sessions"),
//         Span::call_site(),
//     );
//     let mut body_all: Vec<proc_macro2::TokenStream> = vec![];
//     let mut body_back: Vec<proc_macro2::TokenStream> = vec![];
//     gen_session_filter_util(&mut body_all, &mut body_back, statics, node);

//     body_filter_all.push(quote! {
//         #ident_mixed.parser.retain(|#ident|{
//             #( #body_all )*
//         });
//         return !(#ident_mixed.parser.is_empty());
//     });
//     body_filter_back.push(quote! {
//         let #ident = #ident_mixed.parser.back().unwrap();
//         #( #body_back )*
//     });
// }

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
            return true;
        });
    }

    let pred_tokenstream = binary_to_tokens(protocol, field, op, value, statics);
    code.push(quote! {
        if #pred_tokenstream {
            #( #body )*
        }
    });
}
