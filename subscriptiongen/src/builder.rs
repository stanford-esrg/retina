use std::collections::{HashSet, VecDeque};
use crate::prototypes::*;
use serde_yaml::{Value, Mapping, from_reader};
use quote::quote;
use proc_macro2::{Span, Ident};

/// TODO: this is very messy and, if we move forward with this,
/// should be cleaned up. 

pub(crate) struct MethodBuilder {
    fields_str: HashSet<String>,
    fields: Vec<proc_macro2::TokenStream>,
    new: Vec<proc_macro2::TokenStream>,
    update: Vec<proc_macro2::TokenStream>,
    deliver_session_on_match: Vec<proc_macro2::TokenStream>,
    terminate: VecDeque<proc_macro2::TokenStream>,
    parser: Vec<proc_macro2::TokenStream>,
    defs: Vec<proc_macro2::TokenStream>,
    enums: Vec<proc_macro2::TokenStream>,
    subscriptions: Vec<proc_macro2::TokenStream>,
    drop: Vec<proc_macro2::TokenStream>,
    connection_bitmask: usize,
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
            terminate: VecDeque::new(),
            parser: Vec::new(),
            defs: Vec::new(),
            enums: Vec::new(),
            subscriptions: Vec::new(),
            drop: Vec::new(),
            connection_bitmask: 0,
            raw_data: Some(data_in.unwrap()),
        }
    }

    /// Read operations to generate code

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

    pub(crate) fn gen_terminate(&mut self) -> (proc_macro2::TokenStream, Vec<proc_macro2::TokenStream>) {
        let get_conn = match self.terminate.is_empty() {
            true => { quote! {} },
            false => { ConnectionData::get_conn() }
        };
        ( get_conn , Vec::from(std::mem::take(&mut self.terminate)) )
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
    
    pub(crate) fn gen_drop(&mut self) -> Vec<proc_macro2::TokenStream> {
        std::mem::take(&mut self.drop)
    }

    /// Uses `matching` data to determine whether conn_track should
    /// maintain the connection. Note that the filter may also have 
    /// requirements. The framework will continue tracking if the filter 
    /// OR subscription want to keep tracking.
    
    pub(crate) fn match_state(&self) -> proc_macro2::TokenStream {
        let conn_bitmask = syn::LitInt::new(&self.connection_bitmask.to_string(), Span::call_site());
        quote! { 
            if self.match_data.matching_by_bitmask(#conn_bitmask) {
                return ConnState::Tracking;
            }
            ConnState::Remove 
        }
    }

    /// Parse raw data into code.
    pub(crate) fn parse(&mut self) {
        let raw_data = std::mem::take(&mut self.raw_data).unwrap();
        if raw_data.get("subscribed").is_none() {
            panic!("Must specify at least one \"subscribed\"");
        }
        // Subscribable types
        let types = raw_data.get("subscribed").unwrap();
        let iter = types.as_mapping().unwrap();
        // String rep. of required data that will be tracked, across all subscriptions. 
        let mut required_data = HashSet::new();
        let mut required_conn_data = HashSet::new();
        for (k, v) in iter {
            // Customizable
            let subscription_name = k.as_str().expect("Cannot read subscription name"); 
            let subscription_data = v.as_mapping()
                                             .expect(&format!("Cannot interpret subscription data as map: {}", subscription_name));
            self.build_subscription(subscription_data, subscription_name, &mut required_data, &mut required_conn_data);
        }
        for s in required_data {
            self.add_tracked_data(&s);
        }
        if !required_conn_data.is_empty() {
            // Temporary - customizing connection not supported
            self.add_tracked_data("connection");
        }
    }

    /// Build the information necessary for a subscription. 
    /// - The subscription struct
    /// - Subscription delivery
    /// Store data that needs to be tracked for later tracking. 
    fn build_subscription(&mut self, subscription_data: &Mapping, subscription_name: &str, 
                           required_data: &mut HashSet<String>, required_conn_data: &mut HashSet<String>)
    {
        /* Build struct */
        let fields = subscription_data.get("fields")
                            .expect(&format!("Must specify desired fields for \"{}\"", subscription_name))
                            .as_mapping()
                            .expect(&format!("Fields must be interpretable as mapping: \"{}\"", subscription_name));

        let fields: std::collections::HashMap<&str, &Value> = 
                    fields.into_iter()
                    .map( | (k, v) | (k.as_str().unwrap(), v ))
                    .collect();
        let is_connection = fields.contains_key("connection");
        let mut struct_fields = vec![];
        let mut deliver_data = vec![];
        for (field_name, v) in fields {
            let field_value: Option<Vec<&str>> = match v.as_sequence() {
                    Some(seq) => Some(seq.into_iter().map( | v | v.as_str().unwrap() ).collect() ),
                    None => None,
            };
            let (fields, 
                 field_names,
                 extract_field_data) = build_field(field_name, field_value, is_connection);
            struct_fields.push(fields);
            deliver_data.extend(extract_field_data);
            if field_name == "connection" {
                required_conn_data.extend(field_names);
            } else {
                required_data.extend(field_names);
            }
        }

        /* Since data may be shared, need to check and 
         * deliver to callbacks for each index. */
        let name = Ident::new(subscription_name, Span::call_site());

        let struct_deliver = quote! {
            Subscribed::#name(#name {
                #( #deliver_data)*
            })
        };  

        /* Set up data delivery */
        let idxs = subscription_data.get("idx")
                            .expect("Must specify at least one \"idx\"")
                            .as_sequence()
                            .expect("\"idx\" field should be formatted as a list");
        
        for i in idxs {
            let idx = i.as_i64().expect("Found \"idx\" that cannot be parsed as int");
            let subscription_idx = syn::LitInt::new(&idx.to_string(), Span::call_site());
            let from_data = quote! {
                if self.match_data.matched_term_by_idx(#subscription_idx) {
                    subscription.invoke_idx(
                        #struct_deliver,
                        #subscription_idx,
                    );
                }
            };
            if is_connection {
                self.terminate.push_back(from_data);
                self.connection_bitmask |= 0b1 << idx;
            } else {
                self.subscriptions.push(from_data);
            }
        }      

        /* Define type */
        let struct_def = quote! {
            #[derive(Debug)]
            pub struct #name { 
                #( #struct_fields )*
            }
        };
        self.defs.push(struct_def);

        /* Define enum variant */
        let enum_def = quote! { #name(#name), };
        self.enums.push(enum_def);

    }

    /// *Track* data when delivered. E.g., store TLS session in struct. 
    fn add_tracked_data(&mut self, input: &str) {
        if self.fields_str.contains(input) { return; }
        self.fields_str.insert(input.to_string());
        match input {
            "http" => {
                self.fields.push(HttpTransactionData::session_field());
                self.new.push(HttpTransactionData::gen_new());
                self.deliver_session_on_match.push(HttpTransactionData::deliver_session_on_match(
                    self.deliver_session_on_match.is_empty(),
                ));
                self.drop.push(HttpTransactionData::drop());
                self.parser.push(HttpTransactionData::parser());
                // add_data five tuple? 
            },
            "tls" => {
                self.fields.push(TlsHandshakeData::session_field());
                self.new.push(TlsHandshakeData::gen_new());
                self.deliver_session_on_match.push(TlsHandshakeData::deliver_session_on_match(
                    self.deliver_session_on_match.is_empty(),
                ));
                self.drop.push(TlsHandshakeData::drop());
                self.parser.push(TlsHandshakeData::parser());
            },
            "five_tuple" => {
                self.fields.push(FiveTupleData::field());
                self.new.push(FiveTupleData::gen_new());
            },
            "connection" => {
                self.fields.push(ConnectionData::tracked_field());
                self.new.push(ConnectionData::gen_new());
                self.update.push(ConnectionData::gen_update(self.connection_bitmask));
            }
            _ => {
                panic!("Unrecognized field");
            }
        }
    }

}

/// yaml parsing...
pub(crate) fn read_subscriptions(filepath_in: &str) -> proc_macro2::TokenStream {
    let f_in = std::fs::File::open(filepath_in);
    if let Err(e) = f_in {
        panic!("Failed to read config filepath ({}) {:?}", filepath_in, e);
    }
    let data_in = from_reader(f_in.unwrap());
    if let Err(e) = data_in {
        panic!("{:?}", e);
    }
    let raw_data: Value = data_in.unwrap();

    if raw_data.get("num_subscriptions").is_none() {
        panic!("Must specify number of subscriptions");
    }

    let value = raw_data.get("num_subscriptions").unwrap().as_i64().unwrap();
    let num_subscriptions = syn::LitInt::new(&value.to_string(), Span::call_site());

    quote! {
        pub const NUM_SUBSCRIPTIONS: usize = #num_subscriptions;
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