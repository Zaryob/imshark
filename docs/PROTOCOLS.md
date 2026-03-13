# ImShark Supported Protocols & Specification References

This document catalogs every network protocol, encapsulation, and application dissected by ImShark, along with its reference RFC or specification, internal dissector location, and known deviations or design notes.

---

## 1. Link Layer & Capture Formats

| Protocol / Layer | Specification | Implementation File | Key Features & Known Deviations |
|---|---|---|---|
| **Ethernet II / IEEE 802.3** | IEEE 802.3 | [`core/src/packet_parser.cpp`](file:///Users/zaryob/Development/imshark/core/src/packet_parser.cpp) | MAC addresses, EtherType, 802.3 length, FCS extraction. |
| **802.1Q / 802.1ad (VLAN)** | IEEE 802.1Q, 802.1ad | [`core/src/packet_parser.cpp`](file:///Users/zaryob/Development/imshark/core/src/packet_parser.cpp) | Nested tags (QinQ) supported up to 2 outer IDs in filter, arbitrary depth in tree. |
| **IEEE 802.11 (WLAN)** | IEEE 802.11-2020 | [`core/src/dissect/wlan.cpp`](file:///Users/zaryob/Development/imshark/core/src/dissect/wlan.cpp) | Management, Control, Data frames, Beacon/Probe SSID/RSN IE extraction, MAC address translation. WPA decryption intentionally out of scope. |
| **Radiotap** | radiotap.org spec | [`core/src/dissect/wlan.cpp`](file:///Users/zaryob/Development/imshark/core/src/dissect/wlan.cpp) | TSFT, flags, rate, channel frequency, dBm signal/noise. |
| **PPI (Packetized Peripheral Interface)** | CACE / Riverbed PPI spec | [`core/src/dissect/wlan.cpp`](file:///Users/zaryob/Development/imshark/core/src/dissect/wlan.cpp) | PPI header, 802.11 common TLV forwarding. |
| **Linux Cooked (SLL / SLL2)** | tcpdump/libpcap spec | [`core/src/packet_parser.cpp`](file:///Users/zaryob/Development/imshark/core/src/packet_parser.cpp) | LINKTYPE_LINUX_SLL (113), LINKTYPE_LINUX_SLL2 (276) protocol parsing. |
| **Loopback / Null** | BSD / OpenBSD spec | [`core/src/packet_parser.cpp`](file:///Users/zaryob/Development/imshark/core/src/packet_parser.cpp) | 4-byte AF family (AF_INET, AF_INET6) in host and network endianness. |
| **Raw IP** | RFC 791, RFC 8200 | [`core/src/packet_parser.cpp`](file:///Users/zaryob/Development/imshark/core/src/packet_parser.cpp) | DLT 12/14/101; IPv4/IPv6 version nibble dispatch. |
| **LLC / SNAP** | IEEE 802.2 / RFC 1042 | [`core/src/dissect/llc.cpp`](file:///Users/zaryob/Development/imshark/core/src/dissect/llc.cpp) | DSAP/SSAP, Control, OUI, EtherType. |
| **STP / RSTP / MSTP** | IEEE 802.1D / 802.1w | [`core/src/dissect/llc.cpp`](file:///Users/zaryob/Development/imshark/core/src/dissect/llc.cpp) | BPDU type, Root ID, Bridge ID, Port ID, timers. |
| **PPP & PPPoE** | RFC 1661, RFC 2516 | [`core/src/dissect/pppoe.cpp`](file:///Users/zaryob/Development/imshark/core/src/dissect/pppoe.cpp) | PPPoE Discovery (PADI/PADO/PADR/PADS/PADT), Session ID, LCP/IPCP/IPv6CP protocol multiplexing. |
| **MPLS** | RFC 3031, RFC 3032 | [`core/src/dissect/mpls.cpp`](file:///Users/zaryob/Development/imshark/core/src/dissect/mpls.cpp) | Label, Traffic Class (Exp), Bottom-of-Stack bit, TTL. |
| **GRE / ERSPAN** | RFC 1701, RFC 2784, RFC 2890 | [`core/src/dissect/gre.cpp`](file:///Users/zaryob/Development/imshark/core/src/dissect/gre.cpp) | Checksum, Key, Sequence number, Type II/III ERSPAN encapsulation. |
| **IP-in-IP** | RFC 2003, RFC 2473 | [`core/src/dissect/ipip.cpp`](file:///Users/zaryob/Development/imshark/core/src/dissect/ipip.cpp) | IP proto 4 (IPv4 in IPv4) and 41 (IPv6 encapsulation). |
| **LLDP** | IEEE 802.1AB | [`core/src/dissect/lldp.cpp`](file:///Users/zaryob/Development/imshark/core/src/dissect/lldp.cpp) | Chassis ID, Port ID, TTL, System Capabilities TLVs. |
| **LACP** | IEEE 802.3ad / 802.1AX | [`core/src/dissect/lacp.cpp`](file:///Users/zaryob/Development/imshark/core/src/dissect/lacp.cpp) | Actor/Partner System ID, Port, State bitmask. |
| **Ethernet MAC Control** | IEEE 802.3x / 802.1Qbb | [`core/src/dissect/mac_control.cpp`](file:///Users/zaryob/Development/imshark/core/src/dissect/mac_control.cpp) | Opcode 0x0001 (PAUSE time) and 0x0101 (PFC class enable). |
| **IEEE 802.15.4** | IEEE 802.15.4-2020 | [`core/src/dissect/bluetooth.cpp`](file:///Users/zaryob/Development/imshark/core/src/dissect/bluetooth.cpp) | Frame Control, Sequence, Addressing mode, Data / Ack frames. |
| **USB (Linux & USBPcap)** | USB 2.0 / USBPcap spec | [`core/src/dissect/usb.cpp`](file:///Users/zaryob/Development/imshark/core/src/dissect/usb.cpp) | Linux USB (189/220) and USBPcap (249) URB transfer types, Setup packet, Descriptors (Device, Config, Interface, Endpoint, HID). |
| **Bluetooth HCI H4 / Monitor** | Bluetooth Core v5.x | [`core/src/dissect/bluetooth.cpp`](file:///Users/zaryob/Development/imshark/core/src/dissect/bluetooth.cpp) | H4 packet indicator (Cmd, ACL, SCO, Event), Opcode, Status, L2CAP framing, ATT/GATT MTU exchange. |
| **CAN / SocketCAN** | ISO 11898-1 / Linux CAN | [`core/src/dissect/industrial.cpp`](file:///Users/zaryob/Development/imshark/core/src/dissect/industrial.cpp) | Link type 227: Standard and Extended 29-bit CAN IDs, EFF/RTR/ERR flags, payload DLC. |

---

## 2. Network Layer

| Protocol | Specification | Implementation File | Key Features & Known Deviations |
|---|---|---|---|
| **IPv4** | RFC 791 | [`core/src/dissect/ip.cpp`](file:///Users/zaryob/Development/imshark/core/src/dissect/ip.cpp) | Header checksum validation, TTL, fragmentation & reassembly (`ip_reassembly.cpp`), options parsing. |
| **IPv6** | RFC 8200 | [`core/src/dissect/ip.cpp`](file:///Users/zaryob/Development/imshark/core/src/dissect/ip.cpp) | Hop Limit, Next Header chain, Extension headers (Hop-by-Hop, Routing, Fragment header reassembly, Destination Options). |
| **ARP / RARP** | RFC 826, RFC 903 | [`core/src/dissect/arp.cpp`](file:///Users/zaryob/Development/imshark/core/src/dissect/arp.cpp) | Hardware & Protocol types, Request / Reply opcodes, Sender / Target hardware and IP addresses. |
| **ICMP** | RFC 792 | [`core/src/dissect/icmp.cpp`](file:///Users/zaryob/Development/imshark/core/src/dissect/icmp.cpp) | Echo Request/Reply, Unreachable, Redirect, Time Exceeded, Checksum check, Quoted original packet. |
| **ICMPv6** | RFC 4443, RFC 4861 | [`core/src/dissect/icmp.cpp`](file:///Users/zaryob/Development/imshark/core/src/dissect/icmp.cpp) | Neighbor Discovery (NS, NA, RS, RA), Echo Request/Reply, ICMPv6 checksum calculation with pseudo-header. |
| **IGMP / MLD** | RFC 2236, RFC 3376, RFC 2710 | [`core/src/dissect/igmp.cpp`](file:///Users/zaryob/Development/imshark/core/src/dissect/igmp.cpp) | IGMPv1/v2/v3 Query/Report/Leave type and group address, Max Response Time, IGMPv3 report record count, checksum verification. v3 group records and Query fields, and MLD, are not decoded. |
| **OSPFv2 / OSPFv3** | RFC 2328, RFC 5340 | [`core/src/dissect/ospf.cpp`](file:///Users/zaryob/Development/imshark/core/src/dissect/ospf.cpp) | Common header (v2; v3 header with Instance ID), v2 Hello and Database Description with LSA headers, packet checksum (v2 per RFC 2328 D.4, v3 via the IPv6 pseudo header). LSR/LSU/LSAck, LSA bodies, v3 Hello/DD and the LSA Fletcher checksum are not implemented. |
| **IPsec (AH & ESP)** | RFC 4302, RFC 4303 | [`core/src/dissect/ipsec.cpp`](file:///Users/zaryob/Development/imshark/core/src/dissect/ipsec.cpp) | AH (SPI, Sequence, ICV; the inner protocol is shown as Next Header only and is not dissected; IPv6 AH is consumed as an extension header), ESP (SPI, Sequence, encrypted-payload indicator; also ESP-in-UDP on port 4500). |
| **IKEv1 / IKEv2** | RFC 2409, RFC 7296 | [`core/src/dissect/ipsec.cpp`](file:///Users/zaryob/Development/imshark/core/src/dissect/ipsec.cpp) | ISAKMP/IKEv2 header and the generic payload chain (type, length; IKEv2 names per RFC 7296), validated before a UDP 500/4500 datagram is claimed; NAT-T keepalive and Non-ESP marker. Payload contents (SA, KE, ID, CERT, AUTH, SK) and IKE fragmentation are not decoded. |

---

## 3. Transport Layer

| Protocol | Specification | Implementation File | Key Features & Known Deviations |
|---|---|---|---|
| **TCP** | RFC 9293, RFC 7323 | [`core/src/dissect/tcp.cpp`](file:///Users/zaryob/Development/imshark/core/src/dissect/tcp.cpp) | Relative Seq/Ack, Flags (SYN, ACK, FIN, RST, PSH, URG, ECE, CWR), Options (MSS, Window Scale, SACK, Timestamps), Checksum validation, Stream reassembly, Follow TCP Stream. |
| **UDP** | RFC 768 | [`core/src/dissect/udp.cpp`](file:///Users/zaryob/Development/imshark/core/src/dissect/udp.cpp) | Ports, Length, UDP checksum verification (IPv4/IPv6 pseudo-header). |
| **UDP-Lite** | RFC 3828 | [`core/src/dissect/udp.cpp`](file:///Users/zaryob/Development/imshark/core/src/dissect/udp.cpp) | Checksum coverage field and checksum verification (pseudo header carries the full datagram length, RFC 3828), IPv4 and IPv6. |
| **SCTP** | RFC 4960 | [`core/src/dissect/sctp.cpp`](file:///Users/zaryob/Development/imshark/core/src/dissect/sctp.cpp) | Common header (Ports, Verification Tag), Castagnoli CRC-32C validation, generic chunk header list and DATA chunk fields (TSN, stream, SSN, PPID, user data length), clamped to the packet. INIT/SACK/HEARTBEAT/ABORT bodies, DATA reassembly and PPID dissection are not implemented. |

---

## 4. Application Protocols

| Protocol | Specification | Implementation File | Key Features & Known Deviations |
|---|---|---|---|
| **DNS / mDNS** | RFC 1035, RFC 6762 | [`core/src/dissect/dns.cpp`](file:///Users/zaryob/Development/imshark/core/src/dissect/dns.cpp) | Query/Answer parsing, Name compression pointers, Records (A, AAAA, CNAME, MX, TXT, SRV, SOA, PTR, OPT/EDNS0). |
| **DHCP / BOOTP** | RFC 2131, RFC 1542 | [`core/src/dissect/dhcp.cpp`](file:///Users/zaryob/Development/imshark/core/src/dissect/dhcp.cpp) | Message types (Discover, Offer, Request, Ack, etc.), Client IP/MAC, Magic Cookie, Options decoding. |
| **HTTP/1.x** | RFC 9112 | [`core/src/dissect/http.cpp`](file:///Users/zaryob/Development/imshark/core/src/dissect/http.cpp) | Request methods (GET, POST, etc.), URI, Response status codes, Header lines, Content-Length & Chunked transfer framing. |
| **HTTP/2** | RFC 9113, RFC 7541 | [`core/src/dissect/http2.cpp`](file:///Users/zaryob/Development/imshark/core/src/dissect/http2.cpp) | Connection preface, Frame header (DATA, HEADERS, SETTINGS, RST_STREAM, PING, GOAWAY, WINDOW_UPDATE), HPACK static & Huffman table decoding. |
| **TLS** | RFC 5246, RFC 8446 | [`core/src/dissect/tls.cpp`](file:///Users/zaryob/Development/imshark/core/src/dissect/tls.cpp) | TLS 1.0 - 1.3 records, Handshake messages, Client/Server Hello, Cipher Suites, Extensions (SNI, ALPN, Supported Versions), Certificate summary. Decryption support via OpenSSL with SSLKEYLOGFILE or pcapng DSB. |
| **DTLS** | RFC 6347, RFC 9147 | [`core/src/dissect/dtls.cpp`](file:///Users/zaryob/Development/imshark/core/src/dissect/dtls.cpp) | Record header, Handshake fragmentation and reassembly (`network::DatagramReassembler`), HelloVerifyRequest, DTLS 1.2 AES-GCM decryption. |
| **NTP** | RFC 5905 | [`core/src/dissect/ntp.cpp`](file:///Users/zaryob/Development/imshark/core/src/dissect/ntp.cpp) | Leap indicator, Version, Mode, Stratum, Poll, Precision, Reference ID, Timestamps. |
| **SSH** | RFC 4253 | [`core/src/dissect/ssh.cpp`](file:///Users/zaryob/Development/imshark/core/src/dissect/ssh.cpp) | Protocol banner parsing, Binary packet length, Message code, KEXINIT algorithm lists. |
| **BGP** | RFC 4271 | [`core/src/dissect/bgp.cpp`](file:///Users/zaryob/Development/imshark/core/src/dissect/bgp.cpp) | BGP 16-byte marker, Message types (OPEN, UPDATE, NOTIFICATION, KEEPALIVE), AS number, NLRI prefixes. |
| **LDAP** | RFC 4511 | [`core/src/dissect/ldap.cpp`](file:///Users/zaryob/Development/imshark/core/src/dissect/ldap.cpp) | BER/ASN.1 parsing (`core/src/dissect/asn1.h`), Message ID, ProtocolOp (BindRequest, SearchRequest, SearchResultEntry, ModifyRequest). |
| **Kerberos** | RFC 4120 | [`core/src/dissect/kerberos.cpp`](file:///Users/zaryob/Development/imshark/core/src/dissect/kerberos.cpp) | DER/ASN.1 parsing, AS-REQ/REP, TGS-REQ/REP, AP-REQ/REP, KRB-ERROR error codes, PA-DATA, TCP stream framing. |
| **SMB2 / SMB3** | MS-SMB2 | [`core/src/dissect/smb2.cpp`](file:///Users/zaryob/Development/imshark/core/src/dissect/smb2.cpp) | NetBIOS framing, SMB2 magic header, Commands (Negotiate, Session Setup, Tree Connect, Create, Read, Write), NT Status codes. |
| **DCE/RPC** | Open Group C706 | [`core/src/dissect/dcerpc.cpp`](file:///Users/zaryob/Development/imshark/core/src/dissect/dcerpc.cpp) | Connection-oriented PDU header, Packet types (Bind, BindAck, Request, Response), Interface UUID, Opnum, stream framing. |
| **NFS (v3/v4) & ONC RPC** | RFC 1813, RFC 1831, RFC 1833 | [`core/src/dissect/nfs.cpp`](file:///Users/zaryob/Development/imshark/core/src/dissect/nfs.cpp) | ONC RPC Record Marking, XDR parsing (`core/src/dissect/xdr.h`), XID, Program (Portmap, NFS, Mount), Procedure, NFS3 GETATTR call/reply. |
| **PostgreSQL** | PostgreSQL Frontend/Backend Protocol 3.0 | [`core/src/dissect/postgres.cpp`](file:///Users/zaryob/Development/imshark/core/src/dissect/postgres.cpp) | SSLRequest, StartupMessage (user/database parameters), SimpleQuery ('Q'), Auth ('R'), ReadyForQuery ('Z'), CommandComplete ('C'). |
| **MySQL** | MySQL Client/Server Protocol | [`core/src/dissect/mysql.cpp`](file:///Users/zaryob/Development/imshark/core/src/dissect/mysql.cpp) | 3-byte packet length + Sequence ID framing, Server Greeting (proto 10), COM_QUERY (0x03), COM_INIT_DB (0x02), OK/ERR/EOF packets. |
| **TDS (Microsoft SQL Server)** | MS-TDS | [`core/src/dissect/tds.cpp`](file:///Users/zaryob/Development/imshark/core/src/dissect/tds.cpp) | 8-byte TDS header framing, Pre-Login (type 18), SQL Batch (type 1) UTF-16LE query extraction, SPID, Status EOM flags. |
| **SIP & SDP** | RFC 3261, RFC 4566 | [`core/src/dissect/voip.cpp`](file:///Users/zaryob/Development/imshark/core/src/dissect/voip.cpp) | SIP Request line (INVITE, BYE, ACK, REGISTER, etc.), Response status, CSeq, Call-ID, Content-Length framing, SDP session and media descriptions. |
| **RTP & RTCP** | RFC 3550 | [`core/src/dissect/voip.cpp`](file:///Users/zaryob/Development/imshark/core/src/dissect/voip.cpp) | RTP v2 header (Payload Type, Sequence Number, Timestamp, SSRC), RTCP Sender Report (SR) and Receiver Report (RR) packets. |
| **Modbus/TCP** | Modbus Application Protocol v1.1b | [`core/src/dissect/industrial.cpp`](file:///Users/zaryob/Development/imshark/core/src/dissect/industrial.cpp) | MBAP header (Transaction ID, Protocol ID = 0, Length, Unit ID), Function Codes (0x01-0x10), Register start address and quantities. |
| **DNP3** | IEEE 1815-2012 | [`core/src/dissect/industrial.cpp`](file:///Users/zaryob/Development/imshark/core/src/dissect/industrial.cpp) | Link Layer framing (0x0564 sync, length, CRC-16), Source/Destination addresses, Transport layer, Application layer Request/Response Function Codes. |
