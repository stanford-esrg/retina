//! TLS handshake components.
//!
//! See [tls-parser](https://docs.rs/tls-parser/latest/tls_parser/) for dependency type definitions.

use crate::utils::base64;

use serde::Serialize;
use tls_parser::{
    NamedGroup, SignatureScheme, TlsCipherSuiteID, TlsCompressionID, TlsExtensionType, TlsVersion,
};

/// A parsed TLS ClientHello message.
#[derive(Debug, Default, Serialize)]
pub struct ClientHello {
    pub version: TlsVersion,
    #[serde(with = "base64")]
    pub random: Vec<u8>,
    #[serde(with = "base64")]
    pub session_id: Vec<u8>,
    pub cipher_suites: Vec<TlsCipherSuiteID>,
    pub compression_algs: Vec<TlsCompressionID>,
    pub extension_list: Vec<TlsExtensionType>,
    pub server_name: Option<String>,
    pub supported_groups: Vec<NamedGroup>,
    pub ec_point_formats: Vec<u8>,
    pub alpn_protocols: Vec<String>,
    pub signature_algs: Vec<SignatureScheme>,
    pub key_shares: Vec<KeyShareEntry>,
    pub supported_versions: Vec<TlsVersion>,
}

/// A parsed TLS ServerHello message.
#[derive(Debug, Default, Serialize)]
pub struct ServerHello {
    pub version: TlsVersion,
    #[serde(with = "base64")]
    pub random: Vec<u8>,
    #[serde(with = "base64")]
    pub session_id: Vec<u8>,
    pub cipher_suite: TlsCipherSuiteID,
    pub compression_alg: TlsCompressionID,
    pub extension_list: Vec<TlsExtensionType>,
    pub ec_point_formats: Vec<u8>,
    pub alpn_protocol: Option<String>,
    pub key_share: Option<KeyShareEntry>,
    pub selected_version: Option<TlsVersion>,
}

/// A raw X509 certificate.
#[derive(Debug, Default, Serialize)]
pub struct Certificate {
    #[serde(with = "base64")]
    pub raw: Vec<u8>,
    // TODO: parsed certificate
}

/// Key data sent by the server in a ServerKeyExchange message.
#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ServerKeyExchange {
    Ecdh(ServerECDHParams),
    Dh(ServerDHParams),
    Rsa(ServerRSAParams),
    #[serde(with = "base64")]
    Unknown(Vec<u8>),
    // TODO: parse signature
}

impl Default for ServerKeyExchange {
    fn default() -> Self {
        ServerKeyExchange::Unknown(vec![])
    }
}

/// Key data sent by the client in a ClientKeyExchange message.
#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ClientKeyExchange {
    Ecdh(ClientECDHParams),
    Dh(ClientDHParams),
    Rsa(ClientRSAParams),
    #[serde(with = "base64")]
    Unknown(Vec<u8>),
}

impl Default for ClientKeyExchange {
    fn default() -> Self {
        ClientKeyExchange::Unknown(vec![])
    }
}

/// RSA parameters sent by the server in a ServerKeyExchange message. (RSA_EXPORT cipher suites).
#[derive(Debug, Default, Serialize)]
pub struct ServerRSAParams {
    #[serde(with = "base64")]
    pub modulus: Vec<u8>,
    #[serde(with = "base64")]
    pub exponent: Vec<u8>,
}

/// Stores the encrypted premaster secret sent by the client in a ClientKeyExchange message in an
/// RSA handshake.
#[derive(Debug, Default, Serialize)]
pub struct ClientRSAParams {
    #[serde(with = "base64")]
    pub encrypted_pms: Vec<u8>,
}

/// Finite-field Diffie-Hellman parameters sent by the server in a ServerKeyExchange message.
#[derive(Debug, Default, Serialize)]
pub struct ServerDHParams {
    #[serde(with = "base64")]
    pub prime: Vec<u8>,
    #[serde(with = "base64")]
    pub generator: Vec<u8>,
    #[serde(with = "base64")]
    pub kx_data: Vec<u8>,
}

/// Finite-field Diffie-Hellman parameters sent by the client in a ClientKeyExchange message.
#[derive(Debug, Default, Serialize)]
pub struct ClientDHParams {
    #[serde(with = "base64")]
    pub kx_data: Vec<u8>,
}

/// Elliptic-curve Diffie-Hellman parameters sent by the server in a ServerKeyExchange message.
#[derive(Debug, Default, Serialize)]
pub struct ServerECDHParams {
    pub curve: NamedGroup,
    #[serde(with = "base64")]
    pub kx_data: Vec<u8>,
}

/// Elliptic-curve Diffie-Hellman parameters sent by the client in a ClientKeyExchange message.
#[derive(Debug, Default, Serialize)]
pub struct ClientECDHParams {
    #[serde(with = "base64")]
    pub kx_data: Vec<u8>,
}

/// A TLS 1.3 key share entry.
///
/// ## Remarks.
/// TLS 1.3 only. `kx_data` contents are determined by the specified group. For Finite Field DH,
/// `kx_data` contains the DH public value. For ECDH, `kx_data` contains the uncompressed x,y EC
/// point prepended with the value 0x4. See [Key
/// Share](https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.8) for details.
#[derive(Debug, Default, Serialize)]
pub struct KeyShareEntry {
    pub group: NamedGroup,
    #[serde(with = "base64")]
    pub kx_data: Vec<u8>,
}
