use heck::CamelCase;
use proc_macro2::{Ident, Span};
use quote::quote;

use retina_core::filter::ast::*;
use retina_core::filter::ptree::{PTree, PNode};

use crate::utils::*;

pub(crate) fn gen_session_filter(
    ptree: &PTree,
    statics: &mut Vec<proc_macro2::TokenStream>,
    deliver: bool
) -> proc_macro2::TokenStream {
    let mut body: Vec<proc_macro2::TokenStream> = vec![];

    gen_session_filter_util(
        &mut body,
        statics,
        &ptree.root,
    );

    let mut start = quote! {};
    let mut ret = quote! {};
    if !deliver {
        start = quote! { let mut result = retina_core::filter::Actions::new(); };
        ret = quote! { result };
    }

    let session_filter = quote!{
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
) 
{
    let mut first_unary = true; 
    for child in node.children.iter()
    {
        match &child.pred { 
            Predicate::Unary { protocol } => {
                if child.pred.on_packet() {
                    ConnDataFilter::add_unary_pred(
                        code,
                        statics,
                        child,
                        protocol,
                        first_unary,
                        &gen_session_filter_util
                    );
                    first_unary = false;
                } else if child.pred.on_connection() {
                    add_service_pred(code, statics, child, protocol, first_unary);
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
                    ConnDataFilter::add_binary_pred(code, statics, child, protocol, field, op, value,
                                                    &gen_session_filter_util); 
                } else if child.pred.on_session() {
                    add_binary_pred(code, statics, child, protocol, field, op, value);
                } else {
                    panic!("Found binary predicate in connection filter pattern");
                }
            }
        }
    }
}


#[allow(clippy::ptr_arg)]
pub(crate) fn add_service_pred(
    code: &mut Vec<proc_macro2::TokenStream>,
    statics: &mut Vec<proc_macro2::TokenStream>,
    node: &PNode,
    protocol: &ProtocolName,
    first_unary: bool,
) {
    let mut body: Vec<proc_macro2::TokenStream> = vec![];
    gen_session_filter_util(&mut body, statics, node);
    update_body(&mut body, node);

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
    gen_session_filter_util(&mut body, statics, node);
    let pred_tokenstream = binary_to_tokens(protocol, field, op, value, statics);
    update_body(&mut body, node);

    code.push(quote! {
        if #pred_tokenstream {
            #( #body )*
        }
    });
}