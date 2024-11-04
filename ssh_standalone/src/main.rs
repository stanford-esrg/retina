//! SSH parser.
//! 
//! Adapted from [the Rusticata SSH parser] (https://github.com/rusticata/ssh-parser/blob/master/src/ssh.rs)

use pcap::Capture;
use ssh_parser::SshPacket;

fn main() {
    let pcap_path = "../traces/ssh_version_exchange.pcapng";
    // let pcap_path = "../traces/small_flows.pcap";
    let mut cap = Capture::from_file(pcap_path).expect("Error opening pcap. Aborting.");

    // let mut s;
    while let Ok(frame) = cap.next() {
        let pkt_data = frame.data;
        println!("pkt_data: {pkt_data:?}");
        // s = parse_version_exchange(&pkt_data.to_vec());
        // println!("s: {s:#?}");
        probe(&pkt_data.to_vec());
    }
}

// determine if a connection is SSH
fn probe(msg: &Vec<u8>) {
    let ssh_identifier = b"SSH";
    let contains_ssh_identifier = msg.windows(ssh_identifier.len()).any(|window| window == ssh_identifier);
    
    if contains_ssh_identifier {
        println!("SSH\n");
    } else {
        println!("NOT SSH\n");
    }
}

#[derive(Clone, Debug, Default)]
pub struct SshDHClient {
    // pub ssh_msg_kexdh_init: Vec<u8>,
    pub e: Vec<u8>,
}

#[derive(Clone, Debug, Default)]
pub struct SshDHServerResponse {
    // pub ssh_msg_kexdh_reply: Vec<u8>,
    pub pubkey_and_certs: Vec<u8>,
    pub f: Vec<u8>,
    pub signature: Vec<u8>,
}

pub fn parse_dh_client_msg(p: SshPacket) -> SshDHClient {
    match p {
        SshPacket::DiffieHellmanInit(pkt) => { 
            SshDHClient {
                e: pkt.e.to_vec(),
            }
        },
        _ => {
            panic!("Input must be a SSH Diffie-Hellman Client Message.");
        }
    }
}

pub fn parse_dh_server_response(p: SshPacket) -> SshDHServerResponse {
    match p {
        SshPacket::DiffieHellmanReply(pkt) => { 
            SshDHServerResponse {
                pubkey_and_certs: pkt.pubkey_and_cert.to_vec(),
                f: pkt.f.to_vec(),
                signature: pkt.signature.to_vec(),
            }
        },
        _ => {
            panic!("Input must be a SSH Diffie-Hellman Server Response.");
        }
    }
}

pub struct ServiceRequestAndResponse {
    service_name: String,
}

pub fn parse_service_req_or_response(p: SshPacket) -> ServiceRequestAndResponse {
    match p {
        SshPacket::ServiceRequest(pkt) => { 
            ServiceRequestAndResponse {
                service_name: std::str::from_utf8(&pkt).expect("Invalid message.").to_string(),
            }
        },
        _ => {
            panic!("Input must be a Service Request or Service Response.");
        }
    }
}

