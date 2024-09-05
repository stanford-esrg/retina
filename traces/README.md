# traces

A collection of sample packet captures pulled from a variety of sources. 

| Trace              | Source                                                                        | Description                                                                                                     |
|--------------------|-------------------------------------------------------------------------------|-----------------------------------------------------------------------------------------------------------------|
| `small_flows.pcap` | [Tcpreplay Sample Captures](https://tcpreplay.appneta.com/wiki/captures.html) | A synthetic combination of a few different applications and protocols at a relatively low network traffic rate. |
| `tls_ciphers.pcap` | [Wireshark Sample Captures](https://wiki.wireshark.org/SampleCaptures)        | OpenSSL client/server GET requests over TLS 1.2 with 73 different cipher suites.                                |
| `quic_retry.pcapng`| [Wireshark Issue](https://gitlab.com/wireshark/wireshark/-/issues/18757)      | An example of a QUIC Retry Packet. Original Pcap modified to remove CookedLinux and add Ether                   |