macro_rules! unwrap_or_ret_false {
    ( $e:expr ) => {
        match $e {
            Some(x) => x,
            None => return false,
        }
    };
}

#[doc(hidden)]
#[macro_export]
macro_rules! protocol {
    ( $x:expr ) => {
        $crate::filter::ast::ProtocolName($x.to_owned())
    };
}

#[doc(hidden)]
#[macro_export]
macro_rules! field {
    ( $x:expr ) => {
        $crate::filter::ast::FieldName($x.to_owned())
    };
}
