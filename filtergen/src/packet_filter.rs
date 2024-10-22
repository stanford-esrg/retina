use quote::quote;

use crate::utils::*;
use retina_core::filter::ast::*;
use retina_core::filter::ptree::{FilterLayer, PNode, PTree};

pub(crate) fn gen_packet_filter(
    ptree: &PTree,
    statics: &mut Vec<proc_macro2::TokenStream>,
    filter_layer: FilterLayer,
) -> proc_macro2::TokenStream {
    let mut body: Vec<proc_macro2::TokenStream> = vec![];

    // Ensure root is covered
    if !ptree.root.actions.drop() || !ptree.root.deliver.is_empty() {
        update_body(&mut body, &ptree.root, filter_layer, false);
    }

    gen_packet_filter_util(
        &mut body,
        statics,
        &ptree.root,
        filter_layer,
    );

    let body = PacketDataFilter::add_root_pred(&ptree.root, &body);

    let packet_filter = quote! {
        let mut result = retina_core::filter::Actions::new();
        #body
        result
    };
    packet_filter
}

fn gen_packet_filter_util(
    code: &mut Vec<proc_macro2::TokenStream>,
    statics: &mut Vec<proc_macro2::TokenStream>,
    node: &PNode,
    filter_layer: FilterLayer,
) {
    let mut first_unary = true;
    for child in node.children.iter().filter(|n| n.pred.on_packet()) {
        match &child.pred {
            Predicate::Unary { protocol } => {
                PacketDataFilter::add_unary_pred(
                    code,
                    statics,
                    child,
                    node.pred.get_protocol(),
                    protocol,
                    first_unary,
                    filter_layer,
                    &gen_packet_filter_util
                );
                first_unary = false;
            }
            Predicate::Binary {
                protocol,
                field,
                op,
                value,
            } => {
                PacketDataFilter::add_binary_pred(
                    code,
                    statics,
                    child,
                    protocol,
                    field,
                    op,
                    value,
                    filter_layer,
                    &gen_packet_filter_util
                );
            }
        }
    }
}
