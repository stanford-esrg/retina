//! SSH transaction parsing.

pub mod parser;
mod transaction;

use serde::Serialize;

/// Parsed SSH transaction contents.
#[derive(Debug, Default, Serialize, Clone)]
pub struct Ssh {
    /// Client protocol version exchange message.
    pub client_version_exchange: SshVersionExchange,

    /// Server protocol version exchange message.
    pub server_version_exchange: SshVersionExchange,

    /// Client Key Exchange message.
    pub client_key_exchange: SshKeyExchange,

    /// Server Key Exchange message.
    pub server_key_exchange: SshKeyExchange,

    /// Client Diffie-Hellman Key Exchange message.
    pub client_dh_key_exchange: SshDHClient,

    /// Server Diffie-Hellman Key Exchange message.
    pub server_dh_key_exchange: SshDHServerResponse,

    /// Client New Keys message.
    pub client_new_keys: SshNewKeys,

    /// Server New Keys message.
    pub server_new_keys: SshNewKeys,

    /// Client Service Request message.
    pub client_service_request: SshServiceRequest,

    /// Server Service Accept message.
    pub server_service_accept: SshServiceAccept,

    /// Disconnection message. Can be sent by client or server.
    pub disconnect: SshDisconnect,
}

impl Ssh {
    // TODO: implement accessors
    pub fn protocol_version(&self) -> String {
        
    }

    pub fn software_version(&self) -> String {

    }

    pub fn comments(&self) -> Option<String> {

    }
}