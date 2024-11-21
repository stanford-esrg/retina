//! SSH parser.
//! 
//! Adapted from [the Rusticata SSH parser] (https://github.com/rusticata/ssh-parser/blob/master/src/ssh.rs)

use ssh_parser::*;
use pcap::Capture;


#[derive(Clone, Debug, Default, PartialEq)]
pub struct SshVersionExchange {
    pub protoversion: String,
    pub softwareversion: String,
    pub comments: Option<String>,
}

pub fn parse_version_exchange(data: &[u8]) {
    let ssh_identifier = b"SSH-";

    if let Some(contains_ssh_identifier) = data.windows(ssh_identifier.len()).position(|window| window == ssh_identifier).map(|p| &data[p..]) {
        match ssh_parser::parse_ssh_identification(contains_ssh_identifier) {
            Ok((_, (_, ssh_id_string))) => {
                let version_exchange = SshVersionExchange {
                    protoversion: String::from_utf8(ssh_id_string.proto.to_vec()).expect("Invalid message.").clone(),
                    softwareversion: String::from_utf8(ssh_id_string.software.to_vec()).expect("Invalid message.").clone(),
                    comments: if ssh_id_string.comments.map(|b| !b.is_empty()).unwrap_or(false) {
                        let comments_vec = ssh_id_string.comments.map(|b| b.to_vec()).unwrap_or_else(|| Vec::new());
                        Some(String::from_utf8(comments_vec).expect("Invalid message.").clone())
                    } else {
                        None
                    }
                };
                println!("protoversion: {:?}", version_exchange.protoversion);
                println!("softwareversion: {:?}", version_exchange.softwareversion);
                println!("comments: {:?}", version_exchange.comments);
            }
            e => println!("Could not parse SSH version exchange: {:?}", e),
        }
    } else {
        println!("NOT SSH\n");
    }
}

fn main() {
    let pcap_path = "../traces/ssh_version_exchange.pcapng";
    let mut cap = Capture::from_file(pcap_path).expect("Error opening pcap. Aborting.");

    let correct1 = SshVersionExchange {
        protoversion: "2.0".to_string(),
        softwareversion: "OpenSSH_9.8".to_string(),
        comments: None,
    };

    let mut frame = cap.next();
    let mut pkt_data = frame.unwrap().data;

    let correct2 = SshVersionExchange {
        protoversion: "2.0".to_string(),
        softwareversion: "OpenSSH_8.2p1".to_string(),
        comments: Some("Ubuntu-4ubuntu0.11".to_string()),
    };

    frame = cap.next();
    pkt_data = frame.unwrap().data;

    parse_version_exchange(&pkt_data);
}


#[derive(Clone, Debug, PartialEq)]
pub struct SshKeyExchange {
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

fn bytes_to_string_vec(data: &[u8]) -> Vec<String> {
    data.split(|&b| b == b',').map(|chunk| String::from_utf8(chunk.to_vec()).unwrap()).collect()
}

fn parse_key_exchange(data: &[u8]) {
    match ssh_parser::parse_ssh_packet(data) {
        Ok((_, (pkt, _))) => {
            match pkt {
                SshPacket::KeyExchange(pkt) => {
                    let key_exchange = SshKeyExchange {
                        cookie: pkt.cookie.to_vec(),
                        kex_algs: bytes_to_string_vec(pkt.kex_algs),
                        server_host_key_algs: bytes_to_string_vec(pkt.server_host_key_algs),
                        encryption_algs_client_to_server: bytes_to_string_vec(pkt.encr_algs_client_to_server),
                        encryption_algs_server_to_client: bytes_to_string_vec(pkt.encr_algs_server_to_client),
                        mac_algs_client_to_server: bytes_to_string_vec(pkt.mac_algs_client_to_server),
                        mac_algs_server_to_client: bytes_to_string_vec(pkt.mac_algs_server_to_client),
                        compression_algs_client_to_server: bytes_to_string_vec(pkt.comp_algs_client_to_server),
                        compression_algs_server_to_client: bytes_to_string_vec(pkt.comp_algs_server_to_client),
                        languages_client_to_server: if !pkt.langs_client_to_server.is_empty() { Some(bytes_to_string_vec(pkt.langs_client_to_server)) } else { None },
                        languages_server_to_client: if !pkt.langs_server_to_client.is_empty() { Some(bytes_to_string_vec(pkt.langs_server_to_client)) } else { None },
                        first_kex_packet_follows: pkt.first_kex_packet_follows,
                    };
                    println!("kex_algs: {:?}", key_exchange.kex_algs);
                    println!("server_host_key_algs: {:?}", key_exchange.server_host_key_algs);
                    println!("encryption_algs_client_to_server: {:?}", key_exchange.encryption_algs_client_to_server);
                    println!("encryption_algs_server_to_client: {:?}", key_exchange.encryption_algs_server_to_client);
                    println!("mac_algs_client_to_server: {:?}", key_exchange.mac_algs_client_to_server);
                    println!("mac_algs_server_to_client: {:?}", key_exchange.mac_algs_server_to_client);
                    println!("compression_algs_client_to_server: {:?}", key_exchange.compression_algs_client_to_server);
                    println!("compression_algs_server_to_client: {:?}", key_exchange.compression_algs_server_to_client);
                    println!("languages_client_to_server: {:?}", key_exchange.languages_client_to_server);
                    println!("languages_server_to_client: {:?}", key_exchange.languages_server_to_client);
                    println!("first_kex_packet_follows: {:?}", key_exchange.first_kex_packet_follows);
                }
            e => println!("Could not parse SSH key exchange 2: {:?}", e),
            }
        }
        e => println!("Could not parse SSH key exchange 1: {:?}", e),
    }
}


#[derive(Clone, Debug, Default)]
pub struct SshDhInit {
    pub e: Vec<u8>,
}

fn parse_dh_client(data: &[u8]) {
    match ssh_parser::parse_ssh_packet(data) {
        Ok((_, (pkt, _))) => {
            match pkt {
                SshPacket::DiffieHellmanInit(pkt) => {
                    let dh_init = SshDhInit {
                        e: pkt.e.to_vec(),
                    };
                    println!("e: {:?}", dh_init.e);
                }
            e => println!("Could not parse DH init 2: {:?}", e),
            }
        }
        e => println!("Could not parse DH init 1: {:?}", e),
    }
}

#[derive(Clone, Debug, Default)]
pub struct SshDHServerResponse {
    pub pubkey_and_certs: Vec<u8>,
    pub f: Vec<u8>,
    pub signature: Vec<u8>,
}

fn parse_dh_server(data: &[u8]) {
    match ssh_parser::parse_ssh_packet(data) {
        Ok((_, (pkt, _))) => {
            match pkt {
                SshPacket::DiffieHellmanReply(pkt) => {
                    let dh_response = SshDHServerResponse {
                        pubkey_and_certs: pkt.pubkey_and_cert.to_vec(),
                        f: pkt.f.to_vec(),
                        signature: pkt.signature.to_vec(),
                    };
                    println!("pubkey_and_certs: {:?}", dh_response.pubkey_and_certs);
                    println!("f: {:?}", dh_response.f);
                    println!("signature: {:?}", dh_response.signature);
                }
            e => println!("Could not parse DH server response 2: {:?}", e),
            }
        }
        e => println!("Could not parse DH server response 1: {:?}", e),
    }
}
