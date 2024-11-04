use regex::Regex;
use ssh_parser::SshPacket;

// A parsed SSH Version Exchange message.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct SshVersionExchange {
    pub protoversion: String,
    pub softwareversion: String,
    pub comments: Option<String>, // comments are optional
}

pub fn parse_version_exchange(msg: &Vec<u8>) -> Option<SshVersionExchange> {
    // let msg_str = std::str::from_utf8(&msg).expect("Invalid message.");
    let msg_str = String::from_utf8_lossy(msg);
    let pattern = Regex::new(r"SSH-.+\r\n").unwrap();
    let s = pattern.find(&msg_str);

    if let Some(m) = s {
        let split_msg: Vec<&str> = m.as_str().split_whitespace().collect();
        // println!("s: {msg_str:?}");
        let versions_info: Vec<&str> = split_msg[0].split('-').collect();
        // println!("versions_info: {versions_info:?}");
        let protoversion = versions_info[1];
        let softwareversion = versions_info[2];
        Some (SshVersionExchange {
            protoversion: protoversion.to_string(),
            softwareversion: softwareversion.to_string(),
            comments: if split_msg.len() > 1 { Some(split_msg[1].to_string()) } else { None },
        } )
    } else {
        None
    }
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct SshKeyExchange {
    // pub ssh_msg_kexinit: Vec<u8>,
    pub cookie: Vec<u8>,
    pub kex_algs: Vec<u8>,
    pub server_host_key_algs: Vec<u8>,
    pub encryption_algs_client_to_server: Vec<u8>,
    pub encryption_algs_server_to_client: Vec<u8>,
    pub mac_algs_client_to_server: Vec<u8>,
    pub mac_algs_server_to_client: Vec<u8>,
    pub compression_algs_client_to_server: Vec<u8>,
    pub compression_algs_server_to_client: Vec<u8>,
    pub languages_client_to_server: Vec<u8>,
    pub languages_server_to_client: Vec<u8>,
    pub first_kex_packet_follows: bool,
}

pub fn parse_key_exchange(p: SshPacket) -> SshKeyExchange {
    match p {
        SshPacket::KeyExchange(pkt) => { 
            SshKeyExchange {
                cookie: pkt.cookie.to_vec(),
                kex_algs: pkt.kex_algs.to_vec(),
                server_host_key_algs: pkt.server_host_key_algs.to_vec(),
                encryption_algs_client_to_server: pkt.encr_algs_client_to_server.to_vec(),
                encryption_algs_server_to_client: pkt.encr_algs_server_to_client.to_vec(),
                mac_algs_client_to_server: pkt.mac_algs_client_to_server.to_vec(),
                mac_algs_server_to_client: pkt.mac_algs_server_to_client.to_vec(),
                compression_algs_client_to_server: pkt.comp_algs_client_to_server.to_vec(),
                compression_algs_server_to_client: pkt.comp_algs_server_to_client.to_vec(),
                languages_client_to_server: pkt.langs_client_to_server.to_vec(),
                languages_server_to_client: pkt.langs_server_to_client.to_vec(),
                first_kex_packet_follows: pkt.first_kex_packet_follows,
            }
        },
        _ => {
            panic!("Input must be a SSH Key Exchange packet.");
        }
    }
}