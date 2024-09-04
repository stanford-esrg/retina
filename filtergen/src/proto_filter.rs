use quote::quote;

use retina_core::filter::ast::*;
use retina_core::filter::ptree::{PNode, PTree, FilterLayer};
use crate::utils::*;

pub(crate) fn gen_proto_filter(
    ptree: &PTree,
    statics: &mut Vec<proc_macro2::TokenStream>,
) -> proc_macro2::TokenStream {

    let mut body: Vec<proc_macro2::TokenStream> = vec![];

    gen_proto_filter_util(
        &mut body,
        statics,
        &ptree.root,
        FilterLayer::Protocol
    );

    let start = quote! { let mut result = retina_core::filter::Actions::new(); };
    let ret = quote! { result };

    let connection_filter = quote!{
        #start
        #( #body )*
        #ret
    };
    connection_filter
}


fn gen_proto_filter_util(
    code: &mut Vec<proc_macro2::TokenStream>,
    statics: &mut Vec<proc_macro2::TokenStream>,
    node: &PNode,
    _filter_layer: FilterLayer,
)
{
    let mut first_unary = true;
    for child in node.children.iter()
                             .filter(|n|
                                      n.pred.on_packet() || n.pred.on_proto())
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
                        FilterLayer::Protocol,
                        &gen_proto_filter_util
                    );
                    first_unary = false;
                } else if child.pred.on_proto() {
                    ConnDataFilter::add_service_pred(code, statics, child, protocol,
                                                     FilterLayer::Protocol, &gen_proto_filter_util);
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
                    FilterLayer::Protocol,
                    &gen_proto_filter_util
                );
            }
        }
    }
}
