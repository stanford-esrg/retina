pub mod layer3;
pub mod layer4;

pub use layer3::{Ipv4CData, Ipv6CData};
pub use layer4::{UdpCData, TcpCData};

use thiserror::Error;
use anyhow::Result;
use crate::protocols::stream::ConnData;

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