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
    // #[serde(with = "base64")]
    // pub ssh_msg_kexinit: Vec<u8>,
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
    pub languages_client_to_server: Vec<String>,
    pub languages_server_to_client: Vec<String>,
    pub first_kex_packet_follows: bool,
}

#[derive(Debug, Default)]
pub struct SshDhInit {
    // pub ssh_msg_kexdh_init: Vec<u8>,
    pub e: Vec<u8>,
}

#[derive(Debug, Default)]
pub struct SshDhResponse {
    // pub ssh_msg_kexdh_reply: Vec<u8>,
    pub pubkey_and_certs: Vec<u8>,
    pub f: Vec<u8>,
    pub signature: Vec<u8>,
}

// #[derive(Clone, Debug, Default)]
// pub struct SshNewKeys {
//     // pub ssh_msg_newkeys: Vec<u8>,
// }

#[derive(Debug)]
pub struct SshServiceRequest {
    // pub ssh_msg_service_request: Vec<u8>,
    pub service_name: String,
}

#[derive(Debug)]
pub struct SshServiceAccept {
    // pub ssh_msg_service_accept: Vec<u8>,
    pub service_name: String,
}
