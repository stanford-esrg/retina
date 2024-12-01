//! SSH handshake parsing.

pub mod parser;
mod handshake;

use serde::Serialize;

/// Parsed SSH handshake contents.
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
    pub client_dh_key_exchange: SshDhInit,
    /// Server Diffie-Hellman Key Exchange message.
    pub server_dh_key_exchange: SshDhResponse,

    /// Client New Keys message.
    pub client_new_keys: SshPacket::NewKeys,
    /// Server New Keys message.
    pub server_new_keys: SshPacket::NewKeys,

    /// Client Service Request message.
    pub client_service_request: SshServiceRequest,
    /// Server Service Accept message.
    pub server_service_accept: SshServiceAccept,
}

impl Ssh {
    /// Returns the SSH protocol version (e.g. 2.0).
    pub fn protocol_version(&self) -> String {
        self.client_version_exchange.protoversion
    }

    /// Returns the SSH software version.
    pub fn software_version(&self) -> String {
        self.client_version_exchange.softwareversion
    }

    /// Returns comments, or `""` if there are no comments.
    pub fn comments(&self) -> Option<String> {
        match &self.client_version_exchange.comments {
            Some(client_version_exchange) => client_version_exchange.comments,
            None => None,
        }
    }

    /// Returns the key exchange algorithms used in SSH key exchange.
    pub fn key_exchange_algs(&self) -> Vec<String> {
        match &self.client_key_exchange {
            Some(client_key_exchange) => client_key_exchange.kex_algs.iter().map(|c| format!("{}", c)).collect(),
            None => vec![],
        }
    }

    pub fn server_host_key_algs(&self) -> Vec<String> {
        match &self.client_key_exchange {
            Some(client_key_exchange) => client_key_exchange.server_host_key_algs.iter().map(|c| format!("{}", c)).collect(),
            None => vec![],
        }
    }

    pub fn encryption_algs_ctos(&self) -> Vec<String> {
        match &self.client_key_exchange {
            Some(client_key_exchange) => client_key_exchange.encryption_algs_client_to_server.iter().map(|c| format!("{}", c)).collect(),
            None => vec![],
        }
    }

    pub fn encryption_algs_stoc(&self) -> Vec<String> {
        match &self.client_key_exchange {
            Some(client_key_exchange) => client_key_exchange.encryption_algs_server_to_client.iter().map(|c| format!("{}", c)).collect(),
            None => vec![],
        }
    }

    pub fn mac_algs_ctos(&self) -> Vec<String> {
        match &self.client_key_exchange {
            Some(client_key_exchange) => client_key_exchange.mac_algs_client_to_server.iter().map(|c| format!("{}", c)).collect(),
            None => vec![],
        }
    }

    pub fn mac_algs_stoc(&self) -> Vec<String> {
        match &self.client_key_exchange {
            Some(client_key_exchange) => client_key_exchange.mac_algs_server_to_client.iter().map(|c| format!("{}", c)).collect(),
            None => vec![],
        }
    }

    pub fn compression_algs_ctos(&self) -> Vec<String> {
        match &self.client_key_exchange {
            Some(client_key_exchange) => client_key_exchange.compression_algs_client_to_server.iter().map(|c| format!("{}", c)).collect(),
            None => vec![],
        }
    }

    pub fn compression_algs_stoc(&self) -> Vec<String> {
        match &self.client_key_exchange {
            Some(client_key_exchange) => client_key_exchange.compression_algs_server_to_client.iter().map(|c| format!("{}", c)).collect(),
            None => vec![],
        }
    }

    pub fn languages_ctos(&self) -> Option<Vec<String>> {
        match &self.client_key_exchange.languages_client_to_server {
            Some(client_key_exchange) => client_key_exchange.languages_client_to_server.iter().map(|c| format!("{}", c)).collect(),
            None => None,
        }
    }

    pub fn languages_stoc(&self) -> Option<Vec<String>> {
        match &self.client_key_exchange.languages_server_to_client {
            Some(client_key_exchange) => client_key_exchange.languages_server_to_client.iter().map(|c| format!("{}", c)).collect(),
            None => None,
        }
    }

    // TODO: more methods...
}