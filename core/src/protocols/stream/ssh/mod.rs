//! SSH handshake parsing.

mod handshake;
pub mod parser;

pub use self::handshake::*;
use serde::Serialize;

/// Parsed SSH handshake contents.
#[derive(Debug, Default, Serialize)]
pub struct Ssh {
    /// Client protocol version exchange message.
    pub client_version_exchange: Option<SshVersionExchange>,
    /// Server protocol version exchange message.
    pub server_version_exchange: Option<SshVersionExchange>,

    /// Key Exchange message.
    pub key_exchange: Option<SshKeyExchange>,

    /// Client Diffie-Hellman Key Exchange message.
    pub client_dh_key_exchange: Option<SshDhInit>,
    /// Server Diffie-Hellman Key Exchange message.
    pub server_dh_key_exchange: Option<SshDhResponse>,

    /// Client New Keys message.
    pub client_new_keys: Option<SshNewKeys>,
    /// Server New Keys message.
    pub server_new_keys: Option<SshNewKeys>,
}

impl Ssh {
    /// Returns the SSH protocol version used by the client (e.g. 2.0).
    pub fn protocol_version_ctos(&self) -> &str {
        match &self.client_version_exchange {
            Some(client_version_exchange) => match &client_version_exchange.protoversion {
                Some(protoversion) => protoversion.as_str(),
                None => "",
            },
            None => "",
        }
    }

    /// Returns the SSH software version used by the client.
    pub fn software_version_ctos(&self) -> &str {
        match &self.client_version_exchange {
            Some(client_version_exchange) => match &client_version_exchange.softwareversion {
                Some(softwareversion) => softwareversion.as_str(),
                None => "",
            },
            None => "",
        }
    }

    /// Returns comments, or `""` if there are no comments, in the protocol version exchange message sent from the client.
    pub fn comments_ctos(&self) -> &str {
        match &self.client_version_exchange {
            Some(client_version_exchange) => match &client_version_exchange.comments {
                Some(comments) => comments.as_str(),
                None => "",
            },
            None => "",
        }
    }

    /// Returns the SSH protocol version used by the server (e.g. 2.0).
    pub fn protocol_version_stoc(&self) -> &str {
        match &self.server_version_exchange {
            Some(server_version_exchange) => match &server_version_exchange.protoversion {
                Some(protoversion) => protoversion.as_str(),
                None => "",
            },
            None => "",
        }
    }

    /// Returns the SSH software version used by the server.
    pub fn software_version_stoc(&self) -> &str {
        match &self.server_version_exchange {
            Some(server_version_exchange) => match &server_version_exchange.softwareversion {
                Some(softwareversion) => softwareversion.as_str(),
                None => "",
            },
            None => "",
        }
    }

    /// Returns comments, or `""` if there are no comments, in the protocol version exchange message sent from the server.
    pub fn comments_stoc(&self) -> &str {
        match &self.server_version_exchange {
            Some(server_version_exchange) => match &server_version_exchange.comments {
                Some(comments) => comments.as_str(),
                None => "",
            },
            None => "",
        }
    }

    /// Returns the cookie used in SSH key exchange.
    pub fn key_exchange_cookie_stoc(&self) -> Vec<u8> {
        match &self.key_exchange {
            Some(key_exchange) => key_exchange.cookie.to_vec(),
            None => vec![],
        }
    }

    /// Returns the key exchange algorithms used in SSH key exchange.
    pub fn kex_algs_stoc(&self) -> Vec<String> {
        match &self.key_exchange {
            Some(key_exchange) => key_exchange
                .kex_algs
                .iter()
                .map(|c| c.to_string())
                .collect(),
            None => vec![],
        }
    }

    /// Returns the algorithms supported for the server host key.
    pub fn server_host_key_algs_stoc(&self) -> Vec<String> {
        match &self.key_exchange {
            Some(key_exchange) => key_exchange
                .server_host_key_algs
                .iter()
                .map(|c| c.to_string())
                .collect(),
            None => vec![],
        }
    }

    /// Returns the symmetric encryption algorithms (ciphers) supported by the client.
    pub fn encryption_algs_ctos(&self) -> Vec<String> {
        match &self.key_exchange {
            Some(key_exchange) => key_exchange
                .encryption_algs_client_to_server
                .iter()
                .map(|c| c.to_string())
                .collect(),
            None => vec![],
        }
    }

    /// Returns the symmetric encryption algorithms (ciphers) supported by the server.
    pub fn encryption_algs_stoc(&self) -> Vec<String> {
        match &self.key_exchange {
            Some(key_exchange) => key_exchange
                .encryption_algs_server_to_client
                .iter()
                .map(|c| c.to_string())
                .collect(),
            None => vec![],
        }
    }

    /// Returns the MAC algorithms supported by the client.
    pub fn mac_algs_ctos(&self) -> Vec<String> {
        match &self.key_exchange {
            Some(key_exchange) => key_exchange
                .mac_algs_client_to_server
                .iter()
                .map(|c| c.to_string())
                .collect(),
            None => vec![],
        }
    }

    /// Returns the MAC algorithms supported by the server.
    pub fn mac_algs_stoc(&self) -> Vec<String> {
        match &self.key_exchange {
            Some(key_exchange) => key_exchange
                .mac_algs_server_to_client
                .iter()
                .map(|c| c.to_string())
                .collect(),
            None => vec![],
        }
    }

    /// Returns the compression algorithms supported by the client.
    pub fn compression_algs_ctos(&self) -> Vec<String> {
        match &self.key_exchange {
            Some(key_exchange) => key_exchange
                .compression_algs_client_to_server
                .iter()
                .map(|c| c.to_string())
                .collect(),
            None => vec![],
        }
    }

    /// Returns the compression algorithms supported by the server.
    pub fn compression_algs_stoc(&self) -> Vec<String> {
        match &self.key_exchange {
            Some(key_exchange) => key_exchange
                .compression_algs_server_to_client
                .iter()
                .map(|c| c.to_string())
                .collect(),
            None => vec![],
        }
    }

    /// Returns the language tags (if any) supported by the client.
    pub fn languages_ctos(&self) -> Vec<String> {
        match &self.key_exchange {
            Some(key_exchange) => key_exchange
                .languages_client_to_server
                .iter()
                .map(|c| c.to_string())
                .collect(),
            None => vec![],
        }
    }

    /// Returns the language tags (if any) supported by the server.
    pub fn languages_stoc(&self) -> Vec<String> {
        match &self.key_exchange {
            Some(key_exchange) => key_exchange
                .languages_server_to_client
                .iter()
                .map(|c| c.to_string())
                .collect(),
            None => vec![],
        }
    }
}
