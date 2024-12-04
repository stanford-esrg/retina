//! SSH handshake parsing.

mod handshake;
pub mod parser;

pub use self::handshake::*;

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
    /// Returns the SSH protocol version (e.g. 2.0).
    pub fn protocol_version_ctos(&self) -> &str {
        match &self.client_version_exchange {
            Some(client_version_exchange) => match &client_version_exchange.protoversion {
                Some(protoversion) => protoversion.as_str(),
                None => "",
            },
            None => "",
        }
    }

    /// Returns the SSH software version.
    pub fn software_version_ctos(&self) -> &str {
        match &self.client_version_exchange {
            Some(client_version_exchange) => match &client_version_exchange.softwareversion {
                Some(softwareversion) => softwareversion.as_str(),
                None => "",
            }
            None => "",
        }
    }

    /// Returns comments, or `""` if there are no comments.
    pub fn comments_ctos(&self) -> &str {
        match &self.client_version_exchange {
            Some(client_version_exchange) => match &client_version_exchange.comments {
                Some(comments) => comments.as_str(),
                None => "",
            }
            None => "",
        }
    }

    /// Returns the SSH protocol version from server to client.
    pub fn protocol_version_stoc(&self) -> &str {
        match &self.server_version_exchange {
            Some(server_version_exchange) => match &server_version_exchange.protoversion {
                Some(protoversion) => protoversion.as_str(),
                None => "",
            },
            None => "",
        }
    }

    /// Returns the SSH software version from server to client.
    pub fn software_version_stoc(&self) -> &str {
        match &self.server_version_exchange {
            Some(server_version_exchange) => match &server_version_exchange.softwareversion {
                Some(softwareversion) => softwareversion.as_str(),
                None => "",
            }
            None => "",
        }
    }

    /// Returns comments from server to client, or `""` if there are no comments.
    pub fn comments_stoc(&self) -> &str {
        match &self.server_version_exchange {
            Some(server_version_exchange) => match &server_version_exchange.comments {
                Some(comments) => comments.as_str(),
                None => "",
            }
            None => "",
        }
    }

    /// Returns the cookie used in SSH key exchange.
    pub fn key_exchange_cookie_stoc(&self) -> Vec<u8> {
        match &self.key_exchange {
            Some(key_exchange) => key_exchange.cookie.iter().map(|&c| c).collect(),
            None => vec![],
        }
    }

    /// Returns the key exchange algorithms used in SSH key exchange.
    pub fn kex_algs_stoc(&self) -> Vec<String> {
        match &self.key_exchange {
            Some(key_exchange) => key_exchange.kex_algs.iter().map(|c| format!("{}", c)).collect(),
            None => vec![]
        }
    }

    pub fn server_host_key_algs_stoc(&self) -> Vec<String> {
        match &self.key_exchange {
            Some(key_exchange) => key_exchange.server_host_key_algs.iter().map(|c| format!("{}", c)).collect(),
            None => vec![],
        }
    }
    
    pub fn encryption_algs_ctos(&self) -> Vec<String> {
        match &self.key_exchange {
            Some(key_exchange) => key_exchange.encryption_algs_client_to_server.iter().map(|c| format!("{}", c)).collect(),
            None => vec![],
        }
    }

    pub fn encryption_algs_stoc(&self) -> Vec<String> {
        match &self.key_exchange {
            Some(key_exchange) => key_exchange.encryption_algs_server_to_client.iter().map(|c| format!("{}", c)).collect(),
            None => vec![],
        }
    }

    pub fn mac_algs_ctos(&self) -> Vec<String> {
        match &self.key_exchange {
            Some(key_exchange) => key_exchange.mac_algs_client_to_server.iter().map(|c| format!("{}", c)).collect(),
            None => vec![],
        }
    }

    pub fn mac_algs_stoc(&self) -> Vec<String> {
        match &self.key_exchange {
            Some(key_exchange) => key_exchange.mac_algs_server_to_client.iter().map(|c| format!("{}", c)).collect(),
            None => vec![],
        }
    }

    pub fn compression_algs_ctos(&self) -> Vec<String> {
        match &self.key_exchange {
            Some(key_exchange) => key_exchange.compression_algs_client_to_server.iter().map(|c| format!("{}", c)).collect(),
            None => vec![],
        }
    }

    pub fn compression_algs_stoc(&self) -> Vec<String> {
        match &self.key_exchange {
            Some(key_exchange) => key_exchange.compression_algs_server_to_client.iter().map(|c| format!("{}", c)).collect(),
            None => vec![],
        }
    }

    pub fn languages_ctos(&self) -> Vec<String> {
        match &self.key_exchange {
            Some(key_exchange) => key_exchange.languages_client_to_server.iter().map(|c| format!("{}", c)).collect(),
            None => vec![],
        }
    }

    pub fn languages_stoc(&self) -> Vec<String> {
        match &self.key_exchange {
            Some(key_exchange) => key_exchange.languages_server_to_client.iter().map(|c| format!("{}", c)).collect(),
            None => vec![],
        }
    }

    pub fn dh_init_e(&self) -> Vec<u8> {
        match &self.client_dh_key_exchange {
            Some(client_dh_key_exchange) => client_dh_key_exchange.e.iter().map(|&c| c).collect(),
            None => vec![],
        }
    }

    pub fn dh_response_pubkey_and_certs(&self) -> Vec<u8> {
        match &self.client_dh_key_exchange {
            Some(client_dh_key_exchange) => client_dh_key_exchange.e.iter().map(|&c| c).collect(),
            None => vec![],
        }
    }

    pub fn dh_response_f(&self) -> Vec<u8> {
        match &self.client_dh_key_exchange {
            Some(client_dh_key_exchange) => client_dh_key_exchange.e.iter().map(|&c| c).collect(),
            None => vec![],
        }
    }

    pub fn dh_response_signature(&self) -> Vec<u8> {
        match &self.client_dh_key_exchange {
            Some(client_dh_key_exchange) => client_dh_key_exchange.e.iter().map(|&c| c).collect(),
            None => vec![],
        }
    }
}