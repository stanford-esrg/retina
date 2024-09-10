use quote::quote;

use retina_core::filter::ast::*;
use retina_core::filter::ptree::{FilterLayer, PNode, PTree};

use crate::utils::*;

pub(crate) fn gen_session_filter(
    ptree: &PTree,
    statics: &mut Vec<proc_macro2::TokenStream>,
) -> proc_macro2::TokenStream {
    let mut body: Vec<proc_macro2::TokenStream> = vec![];

    gen_session_filter_util(&mut body, statics, &ptree.root, FilterLayer::Session);

    let start = quote! { let mut result = retina_core::filter::Actions::new(); };
    let ret = quote! { result };

    let session_filter = quote! {
        #start
        #( #body )*
        #ret
    };
    session_filter
}

fn gen_session_filter_util(
    code: &mut Vec<proc_macro2::TokenStream>,
    statics: &mut Vec<proc_macro2::TokenStream>,
    node: &PNode,
    _filter_layer: FilterLayer,
) {
    let mut first_unary = true;
    for child in node.children.iter() {
        match &child.pred {
            Predicate::Unary { protocol } => {
                if child.pred.on_packet() {
                    ConnDataFilter::add_unary_pred(
                        code,
                        statics,
                        child,
                        protocol,
                        first_unary,
                        FilterLayer::Session,
                        &gen_session_filter_util,
                    );
                    first_unary = false;
                } else if child.pred.on_proto() {
                    SessionDataFilter::add_service_pred(
                        code,
                        statics,
                        child,
                        protocol,
                        first_unary,
                        FilterLayer::Session,
                        &gen_session_filter_util,
                    );
                    first_unary = false;
                } else {
                    panic!("Found unary predicate in session filter pattern");
                }
            }
            Predicate::Binary {
                protocol,
                field,
                op,
                value,
            } => {
                if child.pred.on_packet() {
                    ConnDataFilter::add_binary_pred(
                        code,
                        statics,
                        child,
                        protocol,
                        field,
                        op,
                        value,
                        FilterLayer::Session,
                        &gen_session_filter_util,
                    );
                } else if child.pred.on_session() {
                    add_binary_pred(code, statics, child, protocol, field, op, value);
                } else {
                    panic!("Found binary predicate in connection filter pattern");
                }
            }
        }
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
) {
    let mut body: Vec<proc_macro2::TokenStream> = vec![];
    gen_session_filter_util(&mut body, statics, node, FilterLayer::Session);
    let pred_tokenstream = binary_to_tokens(protocol, field, op, value, statics);
    update_body(&mut body, node, FilterLayer::Session, false);

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
