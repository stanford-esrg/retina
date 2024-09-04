use quote::quote;
use heck::CamelCase;
use proc_macro2::{Ident, Span};

use retina_core::filter::ast::*;
use retina_core::filter::ptree::{PNode, PTree, FilterLayer};
use crate::utils::*;

pub(crate) fn gen_deliver_filter(
    ptree: &PTree,
    statics: &mut Vec<proc_macro2::TokenStream>,
    filter_layer: FilterLayer
) -> proc_macro2::TokenStream {

    let mut body: Vec<proc_macro2::TokenStream> = vec![];

    gen_deliver_util(
        &mut body,
        statics,
        &ptree.root,
        filter_layer,
    );

    let connection_deliver = quote!{
        #( #body )*
    };
    connection_deliver
}


fn gen_deliver_util(
    code: &mut Vec<proc_macro2::TokenStream>,
    statics: &mut Vec<proc_macro2::TokenStream>,
    node: &PNode,
    filter_layer: FilterLayer,
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
                        filter_layer,
                        &gen_deliver_util
                    );
                    first_unary = false;
                } else if child.pred.on_proto() {
                    ConnDataFilter::add_service_pred(code, statics, child, protocol,
                        filter_layer,
                                                     &gen_deliver_util);
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
                        filter_layer,
                        &gen_deliver_util
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
                        filter_layer
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
    layer: FilterLayer,
) {
    let mut body: Vec<proc_macro2::TokenStream> = vec![];
    gen_deliver_util(&mut body, statics, node, layer);
    update_body(&mut body, node, layer);
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