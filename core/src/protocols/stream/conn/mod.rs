pub mod layer3;
pub mod layer4;

pub use layer3::{Ipv4CData, Ipv6CData};
pub use layer4::{TcpCData, UdpCData};

use crate::protocols::stream::ConnData;
use anyhow::Result;
use thiserror::Error;

#[derive(Error, Debug)]
pub(crate) enum ConnDataError {
    #[error("Invalid protocol")]
    InvalidProtocol,
}

pub trait ConnField {
    fn parse_from(conn: &ConnData) -> Result<Self>
    where
        Self: Sized;
}
