//! SSH handshake components.
//! 

use crate::utils::base64;

use serde::Serialize;

/// A parsed SSH Protocol Version Exchange message.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct SshVersionExchange {
    pub protoversion: Option<String>,
    pub softwareversion: Option<String>,
    pub comments: Option<String>,
}

/// A parsed SSH Key Exchange message.
#[derive(Debug, PartialEq, Serialize)]
pub struct SshKeyExchange {
    #[serde(with = "base64")]
    pub cookie: Vec<u8>,
    pub kex_algs: Vec<String>,
    pub server_host_key_algs: Vec<String>,
    pub encryption_algs_client_to_server: Vec<String>,
    pub encryption_algs_server_to_client: Vec<String>,
    pub mac_algs_client_to_server: Vec<String>,
    pub mac_algs_server_to_client: Vec<String>,
    pub compression_algs_client_to_server: Vec<String>,
    pub compression_algs_server_to_client: Vec<String>,
    pub languages_client_to_server: Option<Vec<String>>,
    pub languages_server_to_client: Option<Vec<String>>,
    pub first_kex_packet_follows: bool,
}

/// A parsed Diffie-Hellman Key Exchange message sent by the client.
#[derive(Debug, Default)]
pub struct SshDhInit {
    pub e: Vec<u8>,
}

/// A parsed Diffie-Hellman Key Exchange message sent by the server.
#[derive(Debug, Default)]
pub struct SshDhResponse {
    pub pubkey_and_certs: Vec<u8>,
    pub f: Vec<u8>,
    pub signature: Vec<u8>,
}

#[derive(Debug, Default)]
pub struct SshNewKeys;
