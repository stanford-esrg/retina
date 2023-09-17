pub(crate) mod tls; 
pub(crate) mod http; 
pub(crate) mod utils;

pub use self::tls::{TlsHandshakeData, TlsSubscription};
pub use self::http::{HttpTransactionData, HttpSubscription};
pub use self::utils::FiveTupleData;

/*
// TODO define consts for fields, use Ident, match on str
pub const FIVE_TUPLE_FIELD: &str = "five_tuple";
pub const HTTP_FIELD: &str = "http";
pub const TLS_FIELD: &str = "tls";
 */
