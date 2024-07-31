use heck::CamelCase;
use proc_macro2::{Ident, Span};
use quote::quote;

use retina_core::filter::ast::*;
use retina_core::filter::ptree::{PNode, PTree};
use crate::utils::*;

// TODO delivery filter won't work for ethernet-only!! 

pub(crate) fn gen_connection_filter(
    ptree: &PTree,
    statics: &mut Vec<proc_macro2::TokenStream>,
    deliver: bool,
) -> proc_macro2::TokenStream {

    let mut body: Vec<proc_macro2::TokenStream> = vec![];

    gen_connection_filter_util(
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

    let connection_filter = quote!{
        #start
        #( #body )*
        #ret
    };
    connection_filter
}


fn gen_connection_filter_util(
    code: &mut Vec<proc_macro2::TokenStream>,
    statics: &mut Vec<proc_macro2::TokenStream>,
    node: &PNode,
) 
{
    let mut first_unary = true; 
    for child in node.children.iter()
                             .filter(|n| 
                                      n.pred.on_packet() || n.pred.on_connection()) 
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
                        &gen_connection_filter_util
                    );
                    first_unary = false;
                } else if child.pred.on_connection() {
                    add_service_pred(code, statics, child, protocol);
                }
            }
            Predicate::Binary {
                protocol,
                field,
                op,
                value,
            } => {
                assert!(child.pred.on_packet());
                ConnDataFilter::add_binary_pred(
                    code,
                    statics,
                    child,
                    protocol,
                    field,
                    op,
                    value,
                    &gen_connection_filter_util
                ); 
            }
        }
    }
}


#[allow(clippy::ptr_arg)]
fn add_service_pred(
    code: &mut Vec<proc_macro2::TokenStream>,
    _statics: &mut Vec<proc_macro2::TokenStream>,
    node: &PNode,
    protocol: &ProtocolName,
) {
    let service_ident = Ident::new(&protocol.name().to_camel_case(), Span::call_site());
    let mut body: Vec<proc_macro2::TokenStream> = vec![];
    update_body(&mut body, node);

    code.push( quote! {
        if matches!(conn.service(), retina_core::protocols::stream::ConnParser::#service_ident { .. }) {
            #( #body )*
        }
    } );
}