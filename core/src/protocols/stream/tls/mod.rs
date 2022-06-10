//! TLS handshake parsing.

mod handshake;
pub(crate) mod parser;

pub use self::handshake::*;

use itertools::Itertools;
use serde::Serialize;
use tls_parser::{TlsCipherSuite, TlsState};

/// GREASE values. See [RFC 8701](https://datatracker.ietf.org/doc/html/rfc8701).
const GREASE_TABLE: &[u16] = &[
    0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a, 0x8a8a, 0x9a9a, 0xaaaa, 0xbaba,
    0xcaca, 0xdada, 0xeaea, 0xfafa,
];

/// Parsed TLS handshake contents.
#[derive(Debug, Default, Serialize)]
pub struct Tls {
    /// ClientHello message.
    pub client_hello: Option<ClientHello>,
    /// ServerHello message.
    pub server_hello: Option<ServerHello>,

    /// Server Certificate chain.
    pub server_certificates: Vec<Certificate>,
    /// Client Certificate chain.
    pub client_certificates: Vec<Certificate>,

    /// ServerKeyExchange message (TLS 1.2 or earlier).
    pub server_key_exchange: Option<ServerKeyExchange>,
    /// ClientKeyExchange message (TLS 1.2 or earlier).
    pub client_key_exchange: Option<ClientKeyExchange>,

    /// TLS state.
    #[serde(skip)]
    state: TlsState,
    /// TCP chunks defragmentation buffer. Defragments TCP segments that arrive over multiple
    /// packets.
    #[serde(skip)]
    tcp_buffer: Vec<u8>,
    /// TLS record defragmentation buffer. Defragments TLS records that arrive over multiple
    /// segments.
    #[serde(skip)]
    record_buffer: Vec<u8>,
}

impl Tls {
    /// Returns the version identifier specified in the ClientHello, or `0` if no ClientHello was
    /// observed in the handshake.
    ///
    /// ## Remarks
    /// This method returns the message protocol version identifier sent in the ClientHello message,
    /// not the record protocol version. This value may also differ from the negotiated handshake
    /// version, such as in the case of TLS 1.3.
    pub fn client_version(&self) -> u16 {
        match &self.client_hello {
            Some(client_hello) => client_hello.version.0,
            None => 0,
        }
    }

    /// Returns the hex-encoded client random, or `""` if no ClientHello was observed in the
    /// handshake.
    pub fn client_random(&self) -> String {
        match &self.client_hello {
            Some(client_hello) => hex::encode(&client_hello.random),
            None => "".to_string(),
        }
    }

    /// Returns the list of cipher suite names supported by the client.
    ///
    /// See [Transport Layer Security (TLS)
    /// Parameters](https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml) for a list
    /// of TLS cipher suites.
    pub fn client_ciphers(&self) -> Vec<String> {
        match &self.client_hello {
            Some(client_hello) => client_hello
                .cipher_suites
                .iter()
                .map(|c| format!("{}", c))
                .collect(),
            None => vec![],
        }
    }

    /// Returns the list of compression method identifiers supported by the client.
    pub fn client_compression_algs(&self) -> Vec<u8> {
        match &self.client_hello {
            Some(client_hello) => client_hello.compression_algs.iter().map(|c| c.0).collect(),
            None => vec![],
        }
    }

    /// Returns the list of ALPN protocol names supported by the client.
    pub fn client_alpn_protocols(&self) -> &[String] {
        match &self.client_hello {
            Some(client_hello) => client_hello.alpn_protocols.as_slice(),
            None => &[],
        }
    }

    /// Returns the list of signature algorithm names supported by the client.
    ///
    /// See [Transport Layer Security (TLS)
    /// Parameters](https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml) for a list
    /// of TLS signature algorithms.
    pub fn client_signature_algs(&self) -> Vec<String> {
        match &self.client_hello {
            Some(client_hello) => client_hello
                .signature_algs
                .iter()
                .map(|s| format!("{}", s))
                .collect(),
            None => vec![],
        }
    }

    /// Returns the list of extension names sent by the client.
    ///
    /// See [Transport Layer Security (TLS)
    /// Extensions](https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml)
    /// for a list of TLS extensions.
    pub fn client_extensions(&self) -> Vec<String> {
        match &self.client_hello {
            Some(client_hello) => client_hello
                .extension_list
                .iter()
                .map(|e| e.to_string())
                .collect(),
            None => vec![],
        }
    }

    /// Returns the name of the server the client is trying to connect to.
    ///
    /// ## Remarks
    /// This method returns the first server name in the server name list.
    pub fn sni(&self) -> &str {
        match &self.client_hello {
            Some(client_hello) => match &client_hello.server_name {
                Some(sni) => sni.as_str(),
                None => "",
            },
            None => "",
        }
    }

    /// Returns the version identifier specified in the ServerHello, or `0` if no ServerHello was
    /// observed in the handshake.
    ///
    /// ## Remarks
    /// This method returns the message protocol version identifier sent in the ServerHello message,
    /// not the record protocol version. This value may also differ from the negotiated handshake
    /// version, such as in the case of TLS 1.3.
    pub fn server_version(&self) -> u16 {
        match &self.server_hello {
            Some(server_hello) => server_hello.version.0,
            None => 0,
        }
    }

    /// Returns the hex-encoded server random, or `""` if no ServerHello was observed in the
    /// handshake.
    pub fn server_random(&self) -> String {
        match &self.server_hello {
            Some(server_hello) => hex::encode(&server_hello.random),
            None => "".to_string(),
        }
    }

    /// Returns the cipher suite name chosen by the server, or `""` if no ServerHello was observed
    /// in the handshake.
    pub fn cipher(&self) -> String {
        match &self.server_hello {
            Some(server_hello) => format!("{}", server_hello.cipher_suite),
            None => "".to_string(),
        }
    }

    /// Returns the cipher suite chosen by the server, or `None` if no ServerHello was observed in
    /// the handshake.
    pub fn cipher_suite(&self) -> Option<&'static TlsCipherSuite> {
        match &self.server_hello {
            Some(server_hello) => server_hello.cipher_suite.get_ciphersuite(),
            None => None,
        }
    }

    /// Returns the compression method identifier chosen by the server, or `0` if no ServerHello was
    /// observed in the handshake.
    pub fn compression_alg(&self) -> u8 {
        match &self.server_hello {
            Some(server_hello) => server_hello.compression_alg.0,
            None => 0,
        }
    }

    /// Returns the list of extension names sent by the server.
    ///
    /// See [Transport Layer Security (TLS)
    /// Extensions](https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml)
    /// for a list of TLS extensions.
    pub fn server_extensions(&self) -> Vec<String> {
        match &self.server_hello {
            Some(server_hello) => server_hello
                .extension_list
                .iter()
                .map(|e| e.to_string())
                .collect(),
            None => vec![],
        }
    }

    /// Returns the negotiated TLS handshake version identifier, or `0` if none was identified.
    ///
    /// ## Remarks
    /// Retina supports parsing SSL 3.0 up to TLS 1.3. This method returns the negotiated handshake
    /// version identifier, even if it does not correspond to a major TLS version (e.g., a draft or
    /// bespoke version number).
    pub fn version(&self) -> u16 {
        match (&self.client_hello, &self.server_hello) {
            (_ch, Some(sh)) => match sh.selected_version {
                Some(version) => version.0,
                None => sh.version.0,
            },
            (Some(ch), None) => ch.version.0,
            (None, None) => 0,
        }
    }

    /// Returns the client JA3 string, or `""` if no ClientHello was observed.
    ///
    /// ## Remarks
    /// The JA3 string is defined as the concatenation of:
    /// `TLSVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats`. See
    /// [salesforce/ja3](https://github.com/salesforce/ja3) for more details.
    pub fn ja3_str(&self) -> String {
        match &self.client_hello {
            Some(ch) => {
                format!(
                    "{},{},{},{},{}",
                    ch.version.0,
                    ch.cipher_suites
                        .iter()
                        .map(|x| x.0)
                        .filter(|x| !GREASE_TABLE.contains(x))
                        .join("-"),
                    ch.extension_list
                        .iter()
                        .map(|x| x.0)
                        .filter(|x| !GREASE_TABLE.contains(x))
                        .join("-"),
                    ch.supported_groups
                        .iter()
                        .map(|x| x.0)
                        .filter(|x| !GREASE_TABLE.contains(x))
                        .join("-"),
                    ch.ec_point_formats.iter().join("-"),
                )
            }
            None => "".to_string(),
        }
    }

    /// Returns the server JA3S string, or `""` if no ServerHello was observed.
    ///
    /// ## Remarks
    /// The JA3S string is defined as the concatenation of: `TLSVersion,Cipher,Extensions`. See
    /// [salesforce/ja3](https://github.com/salesforce/ja3) for more details.
    pub fn ja3s_str(&self) -> String {
        match &self.server_hello {
            Some(sh) => {
                format!(
                    "{},{},{}",
                    sh.version.0,
                    sh.cipher_suite.0,
                    sh.extension_list
                        .iter()
                        .map(|x| x.0)
                        .filter(|x| !GREASE_TABLE.contains(x))
                        .join("-")
                )
            }
            None => "".to_string(),
        }
    }

    /// Returns the JA3 fingerprint.
    pub fn ja3_hash(&self) -> String {
        format!("{:x}", md5::compute(self.ja3_str()))
    }

    /// Returns the JA3S fingerprint.
    pub fn ja3s_hash(&self) -> String {
        format!("{:x}", md5::compute(self.ja3s_str()))
    }
}
