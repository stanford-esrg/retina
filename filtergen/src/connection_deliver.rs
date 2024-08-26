use quote::quote;
use heck::CamelCase;
use proc_macro2::{Ident, Span};

use retina_core::filter::ast::*;
use retina_core::filter::ptree::{PNode, PTree, FilterLayer};
use crate::utils::*;

pub(crate) fn gen_connection_deliver(
    ptree: &PTree,
    statics: &mut Vec<proc_macro2::TokenStream>,
) -> proc_macro2::TokenStream {

    let mut body: Vec<proc_macro2::TokenStream> = vec![];

    gen_connection_deliver_util(
        &mut body,
        statics,
        &ptree.root,
    );

    let connection_filter = quote!{
        #( #body )*
    };
    connection_filter
}


fn gen_connection_deliver_util(
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
                        FilterLayer::ConnectionDeliver,
                        &gen_connection_deliver_util
                    );
                    first_unary = false;
                } else if child.pred.on_connection() {
                    ConnDataFilter::add_service_pred(code, statics, child, protocol, 
                                         FilterLayer::ConnectionDeliver, 
                                                     &gen_connection_deliver_util);
                } else {
                    panic!("Unary predicate on session filter");
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
                        FilterLayer::ConnectionDeliver,
                        &gen_connection_deliver_util
                    );
                } else if child.pred.on_session() {
                    add_session_pred(
                        code,
                        statics,
                        child,
                        protocol,
                        field,
                        op,
                        value,
                    );
                } else {
                    panic!("Binary predicate on protocol filter");
                }
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn add_session_pred(
    code: &mut Vec<proc_macro2::TokenStream>,
    statics: &mut Vec<proc_macro2::TokenStream>,
    node: &PNode,
    protocol: &ProtocolName,
    field: &FieldName,
    op: &BinOp,
    value: &Value,
) {
    let mut body: Vec<proc_macro2::TokenStream> = vec![];
    gen_connection_deliver_util(&mut body, statics, node);
    update_body(&mut body, node, FilterLayer::ConnectionDeliver);
    let pred_tokenstream = binary_to_tokens(protocol, field, op, value, statics);
    
    let service = protocol.name();
    let proto_name = Ident::new(service, Span::call_site());
    let proto_variant = Ident::new(&service.to_camel_case(), Span::call_site());
    let proto_condition = quote! { let retina_core::protocols::stream::SessionData::#proto_variant(#proto_name) = &session.data };

    code.push( 
        quote! {
            for session in tracked.sessions() {
                if #proto_condition  {
                    if #pred_tokenstream {
                        #( #body )*
                    }
                }
            }
        }
    );
}