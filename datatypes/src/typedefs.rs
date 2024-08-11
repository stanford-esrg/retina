use retina_core::filter::datatypes::{Level, DataType};
use lazy_static::lazy_static;
use std::collections::HashMap;

// To add a datatype, add it to the following map
// This is read by the filtergen crate.
lazy_static! {
    pub static ref DATATYPES: HashMap<&'static str, DataType> = 
    { 
        HashMap::from([
            ( 
                "Connection",
                { DataType::new(Level::Connection, false, true) }
            ),
            (
                "HttpTransaction",
                { DataType::new(Level::Session, true, false) }
            )
        ]) 
    };
}