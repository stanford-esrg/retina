use pcap::Capture;

use ssh_parser::parse_ssh_packet;
use ssh_standalone::*;

#[test]
fn test_ssh_version_exchange() {
    let pcap_path = "../traces/ssh_version_exchange.pcapng";
    let mut cap = Capture::from_file(pcap_path).expect("Error opening pcap. Aborting.");

    let correct1 = SshVersionExchange {
        protoversion: "2.0".to_string(),
        softwareversion: "OpenSSH_9.8".to_string(),
        comments: None,
    };

    let mut frame = cap.next();
    let mut pkt_data = frame.unwrap().data;
    let mut s = parse_version_exchange(&pkt_data.to_vec());
    assert_eq!(s, Some(correct1));

    let correct2 = SshVersionExchange {
        protoversion: "2.0".to_string(),
        softwareversion: "OpenSSH_8.2p1".to_string(),
        comments: Some("Ubuntu-4ubuntu0.11".to_string()),
    };

    frame = cap.next();
    pkt_data = frame.unwrap().data;
    s = parse_version_exchange(&pkt_data.to_vec());
    assert_eq!(s, Some(correct2));
}

#[test]
fn test_ssh_key_exchange() {
    let pcap_path = "../traces/ssh_init_key_exchange.pcapng";
    let mut cap = Capture::from_file(pcap_path).expect("Error opening pcap. Aborting.");

    // let correct1 = {

    // }
    
    let mut frame = cap.next();
    let mut pkt_data = frame.unwrap().data;
    println!("pkt_data: {pkt_data:#?}");

    match parse_ssh_packet(&pkt_data) {
        Ok((remaining, (pkt, padding))) => {
            let mut s = parse_key_exchange(pkt);
            println!("s: {s:#?}");
            // assert_eq!(pkt, Some(correct1));
        }
        Err(err) => {
            println!("Error.");
        }
    }
}