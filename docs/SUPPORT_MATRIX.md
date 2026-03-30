# ImShark Support Matrix

This document details the file formats, link types, encapsulation methods, and protocols supported by ImShark across versions v0.1 to v1.9+.

---

## 1. Supported File Formats

- **PCAP** (`.pcap`): Classic libpcap format, little-endian and big-endian, microsecond and nanosecond timestamps.
- **PCAPNG** (`.pcapng`): PCAP Next Generation, Section Header Blocks (SHB), Interface Description Blocks (IDB), Enhanced Packet Blocks (EPB), Simple Packet Blocks (SPB), Interface Statistics Blocks (ISB), and Decryption Secrets Blocks (DSB, type `0x544c534b`).
- **GZIP** (`.gz`): Transparent decompression of `.pcap.gz` and `.pcapng.gz` files via streaming deflate parser.

## 2. Recognized File Formats (Diagnostic Support)

Files with known magic numbers produce specific diagnostic messages (`Desteklenmeyen dosya biçimi: <Biçim>`):
- **Microsoft Network Monitor** (`.cap`, `GMBU`)
- **Sun snoop** (`snoop\0\0\0`)
- **Endace ERF** (record-based header)
- **AIX iptrace** (`iptrace 1.0` / `iptrace 2.0`)

---

## 3. Link Types

| Link Type ID | Name | Description |
|---|---|---|
| 0 | **Null / BSD Loopback** | 4-byte AF family header (AF_INET, AF_INET6) |
| 1 | **Ethernet** | IEEE 802.3 / Ethernet II with FCS extraction |
| 12, 14, 101 | **Raw IP** | Raw IPv4 or IPv6 (nibble dispatch) |
| 105 | **IEEE 802.11** | Direct 802.11 wireless MAC frames |
| 108 | **OpenBSD Loopback** | 4-byte AF family in network byte order |
| 113 | **Linux Cooked v1 (SLL)** | 16-byte Linux cooked packet capture header |
| 127 | **IEEE 802.11 + Radiotap** | Radiotap header (TSFT, flags, rate, channel, dBm signal/noise) |
| 187 | **Bluetooth HCI H4** | UART H4 transport indicator, Command, ACL, SCO, Event |
| 189 | **USB Linux** | Linux USB mon header |
| 192 | **IEEE 802.11 + PPI** | Packetized Peripheral Interface header and TLVs |
| 195, 215 | **IEEE 802.15.4** | Wireless PAN MAC data / ack frames |
| 220 | **USB Linux mmapped** | Memory-mapped Linux USB URB capture |
| 227 | **SocketCAN** | Linux SocketCAN frames (Standard and Extended IDs) |
| 249 | **USBPcap** | USBPcap bulk, control, interrupt header |
| 254 | **Bluetooth Linux Monitor** | Linux Bluetooth subsystem monitor packets |
| 276 | **Linux Cooked v2 (SLL2)** | 20-byte Linux cooked capture v2 header |

---

## 4. Encapsulation Protocols

- **802.1Q / 802.1ad VLAN**: Nested tags (QinQ) supported.
- **MPLS**: Multiprotocol Label Switching labels, Exp, BoS, TTL.
- **GRE / ERSPAN**: Generic Routing Encapsulation (checksum, key, sequence) and ERSPAN Type II/III.
- **IP-in-IP**: Protocol 4 (IPv4 in IPv4) and Protocol 41 (IPv6 in IPv4).
- **PPPoE**: Discovery (PADI/PADO/PADR/PADS/PADT) and Session stages.
- **PPP**: Point-to-Point Protocol (LCP, IPCP, IPv6CP, PAP, CHAP).
- **LLC / SNAP**: Subnetwork Access Protocol and IEEE 802.2 Logical Link Control.
- **Ethernet MAC Control**: 802.3x PAUSE and 802.1Qbb PFC frames.
- **STP / RSTP / MSTP**: Spanning Tree Protocol BPDUs.

---

## 5. Application and Network Protocols

### Network & Transport Layer
| Protocol | Features | Reassembly | Filter Fields |
|---|---|---|---|
| **IPv4** | Options, TTL, Identification, Checksum check | Datagram reassembly | `ip.*`, `ip.src`, `ip.dst`, `ip.addr`, `ip.fragment`, `ip.ttl` |
| **IPv6** | Extension headers (Hop-by-Hop, Routing, Frag, DestOpt) | Fragment reassembly | `ipv6.*`, `ipv6.src`, `ipv6.dst`, `ipv6.addr`, `ipv6.fragment` |
| **ARP / RARP** | Hardware/Protocol types, Sender/Target HW & IP | N/A | `arp` |
| **ICMP / ICMPv6** | Type/Code, Quoted payload, Checksum, NDP | N/A | `icmp.*`, `icmpv6.*` |
| **IGMP / MLD** | IGMPv1/v2/v3 Query/Report/Leave header and group address, v3 record count, checksum (no v3 group records) | N/A | `igmp`, `igmp.type`, `igmp.group` |
| **OSPF** | OSPFv2 Hello, DD with LSA headers; OSPFv3 common header; packet checksum (v2 RFC 2328 D.4, v3 pseudo header). No LSR/LSU/LSAck, LSA bodies or LSA checksum | N/A | `ospf`, `ospf.version`, `ospf.type`, `ospf.router_id`, `ospf.area_id` |
| **IPsec (AH / ESP)** | SPI, Sequence, ICV, encrypted-payload mark; ESP-in-UDP (4500). No inner protocol chaining (AH Next Header only shown); IPv6 AH not dissected | N/A | `ah`, `ah.spi`, `ah.sequence`, `esp`, `esp.spi`, `esp.sequence` |
| **IKEv1 / IKEv2** | ISAKMP/IKEv2 header, generic payload chain, NAT-T keepalive and Non-ESP marker, content-validated on ports 500/4500. No payload contents or fragmentation | N/A | `ike`, `ike.version`, `ike.exchange_type` |
| **TCP** | Options (MSS, WS, SACK, TS), Relative Seq/Ack, Flags, Analysis | TCP stream reassembly | `tcp.*`, `tcp.port`, `tcp.flags.*`, `tcp.analysis.*` |
| **UDP** | Ports, Length, UDP checksum verification | N/A | `udp.*`, `udp.port`, `udp.checksum.status` |
| **UDP-Lite** | RFC 3828 checksum coverage and validation (IPv4, IPv6) | N/A | `udplite` |
| **SCTP** | Verification Tag, Castagnoli CRC-32C, generic chunk list and DATA fields (no INIT/SACK/HEARTBEAT bodies, no reassembly) | N/A | `sctp`, `sctp.srcport`, `sctp.dstport`, `sctp.port`, `sctp.vtag`, `sctp.chunk_type` |

### Application Layer
| Protocol | Features | Stream / Message Framing | Filter Fields |
|---|---|---|---|
| **DNS / mDNS** | Q/A Sections, Name compression, A/AAAA/TXT/MX/SOA/SRV/OPT | Yes (TCP) | `dns.*`, `dns.flags.*`, `dns.qry.name`, `dns.a`, `dns.cname` |
| **DHCP / BOOTP** | Message types, Client IP/MAC, Magic Cookie, Options decoding | N/A (UDP) | `dhcp.*`, `dhcp.option.type` |
| **HTTP/1.x** | Heuristic detection, Method, URI, Status Code, Chunked framing | Yes (TCP) | `http.*`, `http.request.method`, `http.response.code` |
| **HTTP/2** | Frames (DATA, HEADERS, SETTINGS, RST...), HPACK static/Huffman | Yes (TCP) | `http2.*`, `http2.type`, `http2.streamid` |
| **TLS** | TLS 1.0-1.3 records, Hello, SNI, ALPN, Cipher Suites, Keylog decryption | Yes (TCP) | `tls.*`, `tls.handshake.type`, `tls.handshake.extensions_server_name` |
| **DTLS** | Handshake fragments, HelloVerifyRequest, DTLS 1.2 AES-GCM decryption | Datagram reassembler | `dtls.*` |
| **NTP** | Timestamps, Leap indicator, Modes, Stratum, Reference ID | N/A (UDP) | `ntp.*` |
| **SSH** | Banner, KEXINIT algorithms, Message codes | Yes (TCP) | `ssh.*`, `ssh.message_code`, `ssh.protocol`, `ssh.kex_algorithm` |
| **BGP** | BGP marker, OPEN, UPDATE, NOTIFICATION, KEEPALIVE, NLRI prefix | Yes (TCP) | `bgp`, `bgp.type`, `bgp.as`, `bgp.nlri`, `bgp.notification.code` |
| **LDAP** | BER header framing + reassembly, Message ID, Bind (no password), Search (scope, RFC 4515 filter), results with result-code names, Extended / StartTLS (TLS follows) | Yes (TCP) | `ldap`, `ldap.message_id`, `ldap.protocol_op`, `ldap.name`, `ldap.result_code`, `ldap.extended_name` |
| **Kerberos** | RFC 4120 tags per message type, AS/TGS/AP REQ/REP, KRB-ERROR names, PA-DATA types, principal / realm, UDP + TCP record mark | Yes (TCP) | `kerberos`, `kerberos.msg_type`, `kerberos.error_code`, `kerberos.realm`, `kerberos.cname`, `kerberos.sname` |
| **SMB2 / SMB3** | NBSS, compound / async headers, Negotiate dialects, Session Setup (NTLMSSP user), Tree Connect path, Create file name, Read / Write, NT status (MS-ERREF), Transform = encrypted label | Yes (TCP) | `smb2`, `smb2.cmd`, `smb2.nt_status`, `smb2.flags.response`, `smb2.flags.signed`, `smb2.encrypted`, `smb2.dialect`, `smb2.tree`, `smb2.filename`, `smb2.user` |
| **DCE/RPC** | CO PDUs in the sender's byte order, every Bind context + interface name, Bind_ack / nak, Request opnum + object UUID, Fault status | Yes (TCP) | `dcerpc`, `dcerpc.pkt_type`, `dcerpc.opnum`, `dcerpc.cn_call_id`, `dcerpc.if_uuid` |
| **NFS / ONC RPC** | Record marking (TCP), XID, AUTH_SYS, NFS v3 handle / name / offset / count, v4 COMPOUND first operation, Portmap, Mount, reply accept / deny status (no call matching, no results) | Yes (TCP) | `rpc`, `rpc.xid`, `rpc.msgtyp`, `rpc.program`, `rpc.programversion`, `rpc.procedure`, `rpc.state_accept`, `rpc.reply_denied`, `nfs`, `nfs.proc`, `nfs.version`, `nfs.name`, `portmap.proc`, `mount.path` |
| **PostgreSQL** | Startup / SSLRequest (+ TLS follow) / Cancel, typed messages by direction, queries, authentication types, ErrorResponse SQLSTATE | Yes (TCP) | `pgsql`, `pgsql.type`, `pgsql.query`, `pgsql.user`, `pgsql.code`, `pgsql.ssl_request` |
| **MySQL** | Direction-aware: greeting, login (no password hash), SSLRequest (+ TLS follow), commands, OK / ERR / EOF, result set packets | Yes (TCP) | `mysql`, `mysql.command`, `mysql.query`, `mysql.error_code`, `mysql.version`, `mysql.user`, `mysql.packet_number`, `mysql.from_server`, `mysql.ssl_request` |
| **TDS (SQL Server)**| Pre-Login options, wrapped TLS handshake, Login7 (password masked), SQL Batch, RPC, response tokens (ERROR number) | Yes (TCP) | `tds`, `tds.type`, `tds.status`, `tds.spid`, `tds.query`, `tds.user`, `tds.encryption`, `tds.error_number` |
| **SIP / SDP** | Request (INVITE, BYE...), Response codes, Call-ID, Content-Length, SDP | Yes (TCP) / UDP | `sip`, `sip.method`, `sip.status_code`, `sip.call_id` |
| **RTP / RTCP** | RTP v2 header (PT, Seq, Timestamp, SSRC), RTCP SR/RR packets | N/A (UDP) | `rtp`, `rtp.pt`, `rtp.ssrc`, `rtcp`, `rtcp.pt` |
| **Modbus/TCP** | MBAP header (Transaction ID, Unit ID), Function Codes, Registers | Yes (TCP) | `modbus`, `modbus.func_code`, `modbus.unit_id` |
| **DNP3** | Link 0x0564 sync, CRC-16, Source/Dest, Transport/Application FCs | Yes (TCP) / UDP | `dnp3`, `dnp3.func_code` |
| **USB** | Linux & USBPcap URB transfer types, Setup packet, Descriptors | N/A (USB) | `usb`, `usb.device` |
| **Bluetooth** | HCI H4, Linux Monitor, L2CAP, ATT/GATT | N/A (BT) | `bt.handle` |

---

## 6. Known Limitations

- **Decryption:** TLS/DTLS decryption relies on provided session keys (keylog files) or pcapng Decryption Secrets Blocks (DSB); live dynamic key extraction from memory is not supported.
- **Windows Platform:** While build targets and CI matrix for Windows are configured, native hardware testing has not been performed locally.
- **Fuzzing & ASan:** All dissectors are verified under Clang AddressSanitizer and UndefinedBehaviorSanitizer with zero leaks and bounds-checked frame offsets.
