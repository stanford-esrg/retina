use std::collections::HashSet;
use crate::prototypes::*;
use serde_yaml::{Value, from_reader};
use quote::quote;

pub(crate) struct MethodBuilder {
    fields_str: HashSet<String>,
    fields: Vec<proc_macro2::TokenStream>,
    new: Vec<proc_macro2::TokenStream>,
    update: Vec<proc_macro2::TokenStream>,
    deliver_session_on_match: Vec<proc_macro2::TokenStream>,
    terminate: Vec<proc_macro2::TokenStream>,
    parser: Vec<proc_macro2::TokenStream>,
    defs: Vec<proc_macro2::TokenStream>,
    enums: Vec<proc_macro2::TokenStream>,
    subscriptions: Vec<proc_macro2::TokenStream>,
    raw_data: Option<Value>,
}

impl MethodBuilder {

    pub(crate) fn new(filepath_in: &str) -> Self {
        let f_in = std::fs::File::open(filepath_in);
        if let Err(e) = f_in {
            panic!("Failed to read config filepath ({}) {:?}", filepath_in, e);
        }
        let data_in = from_reader(f_in.unwrap());
        if let Err(e) = data_in {
            panic!("{:?}", e);
        }

        Self {
            fields_str: HashSet::new(),
            fields: Vec::new(),
            new: Vec::new(),
            update: Vec::new(),
            deliver_session_on_match: Vec::new(),
            terminate: Vec::new(),
            parser: Vec::new(),
            defs: Vec::new(),
            enums: Vec::new(),
            subscriptions: Vec::new(),
            raw_data: Some(data_in.unwrap()),
        }
    }

    pub(crate) fn gen_struct(&mut self) -> Vec<proc_macro2::TokenStream> {
        std::mem::take(&mut self.fields)
    }

    pub(crate) fn gen_new(&mut self) -> Vec<proc_macro2::TokenStream> {
        std::mem::take(&mut self.new)
    }

    pub(crate) fn gen_update(&mut self) -> Vec<proc_macro2::TokenStream> {
        std::mem::take(&mut self.update)
    }

    pub(crate) fn gen_deliver_session_on_match(&mut self) -> Vec<proc_macro2::TokenStream> {
        std::mem::take(&mut self.deliver_session_on_match)
    }

    pub(crate) fn gen_terminate(&mut self) -> Vec<proc_macro2::TokenStream> {
        std::mem::take(&mut self.terminate)
    }

    pub(crate) fn gen_parsers(&mut self) -> Vec<proc_macro2::TokenStream> {
        std::mem::take(&mut self.parser)
    }

    pub(crate) fn gen_enums(&mut self) -> Vec<proc_macro2::TokenStream> {
        std::mem::take(&mut self.enums)
    }

    pub(crate) fn gen_structs(&mut self) -> Vec<proc_macro2::TokenStream> {
        std::mem::take(&mut self.defs)
    }

    pub(crate) fn gen_subscriptions(&mut self) -> Vec<proc_macro2::TokenStream> {
        std::mem::take(&mut self.subscriptions)
    }

    pub(crate) fn match_state(&self) -> proc_macro2::TokenStream {
        // TODO
        quote! { ConnState::Remove }
    }

    pub(crate) fn parse(&mut self) {
        let raw_data = std::mem::take(&mut self.raw_data).unwrap();
        if raw_data.get("subscribed").is_none() {
            panic!("Must specify at least one \"subscribed\"");
        }
        let types = raw_data.get("subscribed").unwrap();
        let iter = types.as_mapping().unwrap();
        for (k, v) in iter {
            self.add_data(k.as_str().unwrap(), v.as_i64().unwrap());
        }
    }

    fn add_data(&mut self, input: &str, idx: i64) {
        if self.fields_str.contains(input) {
            return;
        }
        self.fields_str.insert(input.to_string());
        match input {
            "http" => {
                self.fields.push(HttpTransactionData::session_field());
                self.new.push(HttpTransactionData::gen_new());
                self.deliver_session_on_match.push(HttpTransactionData::deliver_session_on_match(
                    self.deliver_session_on_match.is_empty(),
                    idx
                ));
                self.parser.push(HttpTransactionData::parser());
                self.add_subscription("http", idx);
                // add_data five tuple? 
            },
            "tls" => {
                self.fields.push(TlsHandshakeData::session_field());
                self.new.push(TlsHandshakeData::gen_new());
                self.deliver_session_on_match.push(TlsHandshakeData::deliver_session_on_match(
                    self.deliver_session_on_match.is_empty(),
                    idx
                ));
                self.parser.push(TlsHandshakeData::parser());
                self.add_subscription("tls", idx);
            },
            "five_tuple" => {
                self.fields.push(FiveTupleData::field());
                self.new.push(FiveTupleData::gen_new());
                // if separate subsc., separate out?
            },
            _ => {
                panic!("Unrecognized field");
            }
        }
    }

    fn add_subscription(&mut self, input: &str, idx: i64) {
        match input {
            "tls" => {
                self.defs.push(TlsSubscription::struct_def());
                self.enums.push(TlsSubscription::enum_def());
                self.subscriptions.push(TlsSubscription::from_data(idx));
            },
            "http" => {
                self.defs.push(HttpSubscription::struct_def());
                self.enums.push(HttpSubscription::enum_def());
                self.subscriptions.push(HttpSubscription::from_data(idx));
            }
            _ => {}
        }
    }

}

/* 
 * TODOs:
 * - Strings and var/enum names should be consts in `prototypes`
 * - Shared fields that aren't copy (pass ref/shared ptr to CB?)
 * - Multiple filters (idx's) for same type
 * - Connections and frames
 * - General cleanup
 * - Customizable types - def. fields
 */