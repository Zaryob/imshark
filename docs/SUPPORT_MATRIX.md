# ImShark Support Matrix

This document details the file formats, link types, encapsulation methods, and protocols supported by ImShark.

## Supported File Formats

- **PCAP** (`.pcap`)
- **PCAPNG** (`.pcapng`)
- **GZIP** (`.gz`): Transparent decompression of `.pcap.gz` and `.pcapng.gz` files via streaming deflate parser.

## Recognized File Formats (Diagnostic Support)

Files with known magic numbers produce specific diagnostic messages (`Desteklenmeyen dosya biçimi: <Biçim>`):
- **Microsoft Network Monitor** (`.cap`, `GMBU`)
- **Sun snoop** (`snoop\0\0\0`)
- **Endace ERF** (record-based header)
- **AIX iptrace** (`iptrace 1.0` / `iptrace 2.0`)


## Link Types

- **Ethernet** (LINKTYPE_ETHERNET / 1)
- **Linux Cooked Capture v1 / v2** (SLL / SLL2)
- **Null / Loopback**
- **Raw IP** (IPv4 / IPv6)
- **IEEE 802.11** (Wi-Fi) with Radiotap and PPI headers

## Encapsulation Protocols

- **802.1Q VLAN** (Nested tags supported)
- **MPLS** (Multiprotocol Label Switching)
- **GRE** (Generic Routing Encapsulation) including ERSPAN
- **IP-in-IP** (IPv4 and IPv6-in-IP)
- **PPPoE** (Discovery and Session stages)
- **PPP** (Point-to-Point Protocol)
- **LLC / SNAP**

## Application and Network Protocols

### Network & Transport Layer
| Protocol | Features | TCP Reassembly | Filter Fields |
|----------|----------|----------------|---------------|
| **IPv4** | Options, Fragmentation & Reassembly | N/A | `ip.*`, `ip.src`, `ip.dst`, `ip.fragment` |
| **IPv6** | Extension Headers, Fragmentation & Reassembly | N/A | `ipv6.*`, `ipv6.src`, `ipv6.dst` |
| **ARP/RARP** | Full decode | N/A | `arp` |
| **ICMP/ICMPv6** | Type/Code names, Quoted packets, Echo IDs, NDP | N/A | `icmp.*`, `icmpv6.*` |
| **TCP** | Options, Relative Seq/Ack, Flags, Window scaling, Stream Follow | Yes | `tcp.*`, `tcp.port`, `tcp.flags.*`, `tcp.analysis.*` |
| **UDP** | Ports, Length, Checksum | N/A | `udp.*`, `udp.port` |

### Application Layer
| Protocol | Features | TCP Reassembly | Filter Fields |
|----------|----------|----------------|---------------|
| **DNS / mDNS** | Headers, Flags, Q/A Sections, A/AAAA/TXT/MX/SOA/SRV/OPT | Yes (DNS over TCP) | `dns.*`, `dns.flags.*`, `dns.qry.name`, `dns.a` |
| **HTTP/1.x** | Heuristic detection, Method, URI, Status Code, Headers | Yes | `http.*`, `http.request.method`, `http.response.code` |
| **HTTP/2** | Frames, HPACK decoding | Yes | `http2.*` |
| **TLS** | Heuristic detection, SNI, Handshake types, Version | Yes | `tls.*`, `tls.handshake.type`, `tls.handshake.extensions_server_name` |
| **DTLS** | Handshake fragments, UDP sessions | N/A | `dtls.*` |
| **DHCP** | Options decode | N/A | `dhcp.*`, `dhcp.option.type` |
| **NTP** | Timestamps, Modes | N/A | `ntp.*` |
| **SNMP, Telnet, SMTP, BGP, FTP, TFTP, SSH** | Basic summary dissection and port mapping | Stream dependent | basic protocol matching |
| **LLDP, STP, LACP, MAC Control** | Basic L2 protocol structures | N/A | `lldp`, `stp`, `lacp` |

*(Note: Dissectors utilize `app_type`, `app_flags`, `app_code`, `app_text`, and `app_text2` summary fields to populate the filter engine efficiently without touching the underlying PCAP file.)*

## Known Limitations

- **Decryption:** TLS/DTLS decryption relies on provided session keys (keylog files); dynamic key extraction from the environment is not supported out-of-the-box.
- **Windows Platform:** While build targets for Windows have been configured, they have not been extensively verified on native Windows machines yet.
- **Stateful UDP Reassembly:** Other than specific protocols like IPv4/v6 fragmentation and DTLS handshakes, generic UDP fragmentation reassembly is limited.
