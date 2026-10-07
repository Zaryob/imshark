# ImShark Support Matrix

This document describes the file formats, link types, encapsulations and protocols implemented in the current source tree. Historical roadmap labels are not release version numbers.

Every row states what the code decodes today. "Filter Fields" lists names that exist in the filter table (the field modules `core/src/dissect/*_fields.cpp`); "none yet" means the protocol has no display-filter fields of its own (the details are in the tree and the Info column). Functional limits per area are in [KNOWN_ISSUES.md](KNOWN_ISSUES.md), specifications and implementation files in [PROTOCOLS.md](PROTOCOLS.md). Many newer protocols are covered by hand-built messages and truncation/mutation sweeps; optional real-capture hooks skip when no matching corpus file is available. See the corpus manifest for the evidence available per capture.

---

## 0. Decode Chains (file format -> link type -> encapsulation -> protocol -> fields / decryption)

This is the path a packet takes through the code, so you can read what a given capture will show. Each step names the
function that makes the hand-over (`core/src/capture_reader.cpp`, `core/src/packet_parser.cpp`, the registrations in
`core/src/dissect/registry.cpp`); sections 1 to 5 below hold the details per item.

| File format | Link type (section 3) | Encapsulation (section 4) | Network / transport | Application protocols (section 5) | Decoded fields / decryption |
|---|---|---|---|---|---|
| pcap, pcapng, either gzip-compressed | **Ethernet (1)**, with optional FCS | 802.1Q / 802.1ad / 0x9100 tags, then by EtherType: MPLS, PPPoE -> PPP, GRE / ERSPAN, IP-in-IP (via IP), LLC / SNAP (frames with a length field) -> STP | IPv4, IPv6 (fragment reassembly), ICMP, ICMPv6, IGMP, OSPF, SCTP, UDP-Lite, AH / ESP, TCP, UDP | all of section 5 | summary columns, details tree, registered summary fields where the protocol has them; TLS / DTLS decryption by key log or pcapng DSB |
| same | **Linux cooked v1 / v2 (113, 276)**, **Null / OpenBSD loopback (0, 108)**, **Raw IP (12, 14, 101)** | the EtherType (cooked) or the address family / IP version nibble (the others) | as above | as above | as above |
| same | **PPP (9)** | PPP: LCP, IPCP, IPv6CP, PAP, CHAP | IPv4, IPv6 | as above | as above |
| same | **802.11 (105)**, **Radiotap (127)**, **PPI (192)** | 802.11 MAC frames; Radiotap and PPI headers are unwrapped first; cleartext data frames with LLC / SNAP continue by EtherType (IPv4, IPv6, ARP, EAPOL) | as above | as above | 802.11 header fields (`wlan.*`); WPA decryption is not done, protected frames are shown as protected data |
| same | **802.15.4 (195, 215, 230)**, **SocketCAN (227)** | none | none | none | MAC / CAN header fields, data bytes |
| same | **USB Linux (189, 220)**, **USBPcap (249)** | none | none | none | URB / IRP header, setup packet, descriptors (`usb.*`) |
| same | **Bluetooth HCI H4 (187)**, **Linux Monitor (254)** | none | none | HCI -> L2CAP -> ATT | `bt.*`; no L2CAP reassembly |
| same | any other id | none | none | none | shown as "Unsupported link type N" |

Within the network / transport column the hand-over to an application protocol is, in order: a stream protocol or a
dissector registered for the TCP / UDP port (destination port first), a content heuristic (HTTP, TLS, HTTP/2, DNS, DTLS),
then Decode As rules, which replace the port registration. TLS found inside STARTTLS-style upgrades (SMTP, LDAP, PostgreSQL,
MySQL) is dissected as TLS from the upgrade on. **Decode As** offers these protocol names (a name is offered for the
transports it supports):
`BGP`, `DCERPC`, `DHCP`, `DNP3`, `DNS`, `DTLS`, `FTP`, `FTP-DATA`, `HTTP`, `HTTP2`, `Kerberos`, `LDAP`, `MDNS`, `Modbus`,
`MySQL`, `NFS`, `NTP`, `PGSQL`, `Portmap`, `RTCP`, `RTP`, `RTSP`, `SCTP`, `SIP`, `SMB2`, `SMTP`, `SNMP`, `SSH`, `TDS`, `Telnet`,
`TFTP`, `TLS`.

Every display-filter field of every row is listed with its type and description in the generated
[FILTER_FIELDS.md](FILTER_FIELDS.md). Tests in `tests/test_docs.cpp` fail when a field, a decoded link type id or a Decode As
name is missing from these documents.

---

## 1. Supported File Formats

- **PCAP** (`.pcap`): Classic libpcap format, little-endian and big-endian, microsecond and nanosecond timestamps.
- **PCAPNG** (`.pcapng`): PCAP Next Generation, Section Header Blocks (SHB), Interface Description Blocks (IDB), Enhanced Packet Blocks (EPB), Simple Packet Blocks (SPB), Interface Statistics Blocks (ISB), and Decryption Secrets Blocks (DSB, type `0x544c534b`).
- **GZIP** (`.gz`): Transparent decompression of `.pcap.gz` and `.pcapng.gz` files via streaming deflate parser.

- **Sun snoop** (`.snoop`, `snoop\0\0\0`): RFC 1761 version 2, big endian, 24 byte record headers with padding to 4 bytes, microsecond timestamps. Datalink types 0 and 4 load as Ethernet, 2 as Token Ring (6) and 8 as FDDI (10) (those two have no dissector: the packet list says "Unsupported link type"); other types are shown as raw data.
- **Microsoft Network Monitor 2.x** (`.cap`, `GMBU`): little endian, frames located through the frame table at the end of the file, capture start from the header's SYSTEMTIME (taken as UTC) plus the per-frame microsecond offset. MAC type 1 loads as Ethernet, 2 as Token Ring and 3 as FDDI (no dissector); other media (ATM, wireless WAN, ...) are shown as raw data. Version 1.x files are refused with a message.
- **Endace ERF** (`.erf`, no magic number: recognised by a plausible first record header, type 1-27, record length >= 16, wire length <= record length unless the truncated flag is set): 32.32 fixed point little endian timestamps, big endian record header, extension header chain, Ethernet pad and record padding. Ethernet record types (2, 11, 16, 20) load as Ethernet, IPv4/IPv6 records (22, 23) as raw IP (101), packet over SONET records with PPP-in-HDLC framing (`ff 03`) as PPP (9); counter and META records (13, 14, 26) carry no packet and are skipped; every other record type (ATM, AAL, multi-channel, InfiniBand, Cisco HDLC, ...) is shown as raw data.
- **AIX iptrace 2.0** (`.iptrace`, `iptrace 2.0`): documented subset (see [KNOWN_ISSUES.md](KNOWN_ISSUES.md)), big endian, 40 byte record headers with nanosecond timestamps and an interface type: 6 and 7 load as Ethernet, 9 as Token Ring and 0x0f as FDDI (no dissector), other types as raw data. iptrace 1.0 is refused with a message.

Frames of a medium without a mapping get the link type 147 (the "user" link type); the packet list says "Unsupported link type 147", the bytes are visible as data and the load message says how many frames were affected. The format is chosen by the magic number, not the extension.

## 2. Recognized But Not Readable

Only the gzip wrapper is not read by a `CaptureFileReader` of its own (the application's loader unpacks it first). Any other file whose first bytes match no format is reported as `Unsupported file format: unknown magic number xx xx xx xx`.

---

## 3. Link Types

| Link Type ID | Name | Description |
|---|---|---|
| 0 | **Null / BSD Loopback** | 4-byte AF family header (AF_INET, AF_INET6) |
| 1 | **Ethernet** | IEEE 802.3 / Ethernet II with FCS extraction |
| 12, 14, 101 | **Raw IP** | Raw IPv4 or IPv6 (nibble dispatch) |
| 9 | **PPP** | Point-to-Point Protocol frames (see PPP below) |
| 105 | **IEEE 802.11** | Direct 802.11 wireless MAC frames (`wlan.*`) |
| 108 | **OpenBSD Loopback** | 4-byte AF family in network byte order |
| 113 | **Linux Cooked v1 (SLL)** | 16-byte Linux cooked packet capture header |
| 127 | **IEEE 802.11 + Radiotap** | Radiotap header (TSFT, flags, rate, channel, dBm signal/noise) |
| 187 | **Bluetooth HCI H4** | H4 indicator; Command, Event, ACL (handle, PB/BC, lengths), SCO/ISO type only; L2CAP header and ATT opcode/MTU/handle |
| 189 | **USB Linux** | usbmon 48-byte header, setup packet, descriptors of GET_DESCRIPTOR completions |
| 192 | **IEEE 802.11 + PPI** | Packetized Peripheral Interface header and TLVs |
| 195, 215, 230 | **IEEE 802.15.4** | MAC Frame Control and sequence number; 195 with 2-byte FCS, 215 with the non-ASK PHY header, 230 without FCS |
| 220 | **USB Linux mmapped** | usbmon 64-byte header with the mmapped extension |
| 227 | **SocketCAN** | Linux SocketCAN frames: Standard and Extended IDs, RTR/error flags, data; CAN FD (72 bytes) |
| 249 | **USBPcap** | USBPcap 27-byte header, control stage, setup packet, descriptors of GET_DESCRIPTOR completions |
| 254 | **Bluetooth Linux Monitor** | 4-byte big-endian adapter id + opcode pseudo header, HCI command/event/ACL payload |
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
- **STP / RSTP / MSTP**: Spanning Tree Protocol BPDUs (`stp.*`).
- **LLDP** (`lldp.*`), **LACP** (`lacp.*`, in `slow_protocols.cpp`) and **EAPOL / 802.1X** (`eapol.*`: EAPOL-Key, EAP).

---

## 5. Application and Network Protocols

### Network & Transport Layer
| Protocol | Features | Reassembly | Filter Fields |
|---|---|---|---|
| **IPv4** | Options, TTL, Identification, Checksum check | Datagram reassembly | `ip.*`, `ip.src`, `ip.dst`, `ip.addr`, `ip.fragment`, `ip.ttl` |
| **IPv6** | Extension headers (Hop-by-Hop, Routing, Frag, DestOpt) | Fragment reassembly | `ipv6.*`, `ipv6.src`, `ipv6.dst`, `ipv6.addr`, `ipv6.fragment` |
| **ARP / RARP** | Hardware/Protocol types, Sender/Target HW & IP | N/A | `arp` |
| **ICMP / ICMPv6** | Type/Code, Quoted payload, Checksum, NDP | N/A | `icmp.*`, `icmpv6.*` |
| **IGMP / MLD** | IGMPv1/v2/v3 Query/Report/Leave header and group address, checksum; v3 Query flags (S, QRV), QQIC and source list, v3 Report group records with sources and auxiliary data (counts bounded by the message, contradictions Malformed). MLD is decoded by the ICMPv6 dissector | N/A | `igmp`, `igmp.type`, `igmp.group`, `igmp.version`, `igmp.num_records`, `igmp.num_sources` |
| **OSPF** | OSPFv2 and OSPFv3 Hello, DD, LSR, LSU and LSAck; v2 authentication fields (null, simple password, MD5 key id / sequence / trailing digest); LSA bodies in LSUs for v2 types 1-5 and 7 and the v3 Router, Network, Inter-Area-Prefix, Inter-Area-Router, AS-External, NSSA, Link and Intra-Area-Prefix LSAs; packet checksum (v2 RFC 2328 D.4, v3 pseudo header); LSA Fletcher checksum where the whole LSA is present (LSU). Opaque LSAs are named, bodies not decoded | N/A | `ospf`, `ospf.version`, `ospf.type`, `ospf.router_id`, `ospf.area_id`, `ospf.lsa.checksum.status`, `ospf.lsa.count`, `ospf.auth.type`, `ospf.instance_id` |
| **IPsec (AH / ESP)** | AH on IPv4 and IPv6: SPI, Sequence, ICV and the protected protocol (transport and tunnel mode). ESP: SPI, Sequence, encrypted-payload mark; ESP-in-UDP (4500); ESP-NULL heuristic (setting, off by default) dissects a payload that looks unencrypted | N/A | `ah`, `ah.spi`, `ah.sequence`, `esp`, `esp.spi`, `esp.sequence`, `esp.null` (the numbers need the capture's IPsec table in the filter context) |
| **IKEv1 / IKEv2** | ISAKMP/IKEv2 header, NAT-T keepalive and Non-ESP marker, content-validated on ports 500/4500; IKEv2 and IKEv1 payload contents (SA, KE, Nonce, ID, CERT, CERTREQ, AUTH, Notify, Delete, VID, TS, CP, EAP, NAT-D); SK / SKF and IKEv1 encrypted messages labelled, not decoded; IKEv2 fragments labelled with number / total, not reassembled | N/A | `ike`, `ike.version`, `ike.exchange_type`, `ike.message_id`, `ike.initiator_spi`, `ike.responder_spi`, `ike.notify.type`, `ike.fragment`, `ike.fragment.number`, `ike.fragment.total` |
| **TCP** | Options (MSS, WS, SACK, TS), Relative Seq/Ack, Flags, Analysis | TCP stream reassembly | `tcp.*`, `tcp.port`, `tcp.flags.*`, `tcp.analysis.*` |
| **UDP** | Ports, Length, UDP checksum verification | N/A | `udp.*`, `udp.port`, `udp.checksum.status` |
| **UDP-Lite** | RFC 3828 checksum coverage and validation (IPv4, IPv6) | N/A | `udplite` |
| **SCTP** | IP protocol 132 and UDP 9899; Verification Tag, Castagnoli CRC-32C, chunk bodies (DATA, I-DATA, INIT, INIT ACK, SACK, HEARTBEAT, ABORT, ERROR, SHUTDOWN*, COOKIE*, ECNE, CWR, FORWARD-TSN, I-FORWARD-TSN) and parameters, DATA / I-DATA fragment reassembly per association, stream and SSN / MID, per-stream totals, payload protocol names | Datagram reassembler (fragments of one user message) | `sctp`, `sctp.srcport`, `sctp.dstport`, `sctp.port`, `sctp.vtag`, `sctp.chunk_type`, `sctp.checksum.status`, `sctp.data`, `sctp.data.tsn`, `sctp.data.sid`, `sctp.data.ssn`, `sctp.data.ppid`, `sctp.data.idata`, `sctp.data.fragment`, `sctp.data.unordered`, `sctp.data.retransmission`, `sctp.reassembled` |

### Application Layer
| Protocol | Features | Stream / Message Framing | Filter Fields |
|---|---|---|---|
| **DNS / mDNS** | Q/A Sections, Name compression, A/AAAA/TXT/MX/SOA/SRV/OPT | Yes (TCP) | `dns`, `dns.qry.name`, `dns.qry.type`, `dns.flags.response`, `dns.flags.rcode`, `dns.flags.truncated` |
| **DHCP / BOOTP** | Message types, Client IP/MAC, Magic Cookie, Options decoding | N/A (UDP) | `dhcp`, `dhcp.type`, `dhcp.option.hostname` |
| **HTTP/1.x** | Heuristic detection, Method, URI, Status Code, Chunked framing | Yes (TCP) | `http.*`, `http.request.method`, `http.response.code` |
| **HTTP/2** | Frames (DATA, HEADERS, SETTINGS, RST...), HPACK static/Huffman | Yes (TCP) | `http2.*`, `http2.type`, `http2.streamid` |
| **TLS** | TLS 1.0-1.3 records, Hello, SNI, ALPN, Cipher Suites, Keylog decryption | Yes (TCP) | `tls.*`, `tls.handshake.type`, `tls.handshake.extensions_server_name` |
| **DTLS** | Handshake fragments, HelloVerifyRequest, DTLS 1.2 AES-GCM decryption | Datagram reassembler | `dtls.*` |
| **NTP** | Timestamps, Leap indicator, Modes, Stratum, Reference ID | N/A (UDP) | `ntp.*` |
| **SSH** | Banner, KEXINIT algorithms, Message codes, encrypted-packet mark | No (one segment at a time) | `ssh.*`, `ssh.message_code`, `ssh.protocol`, `ssh.kex_algorithm` |
| **SNMP** | v1 / v2c / v3 (USM), PDU types, varbinds, MIB names | N/A (UDP) | `snmp`, `snmp.version`, `snmp.community`, `snmp.pdu_type`, `snmp.request_id`, `snmp.error_status`, `snmp.oid` |
| **Telnet** | IAC commands, option negotiation, SB/NAWS/Terminal-Type | No | `telnet`, `telnet.cmd`, `telnet.subcmd`, `telnet.data` |
| **SMTP** | Command/reply split, multi-line replies, addresses, headers, STARTTLS (TLS follows) | No | `smtp`, `smtp.command`, `smtp.param`, `smtp.req`, `smtp.rsp`, `smtp.response.code` |
| **FTP / FTP-DATA** | Commands, replies, PASV / EPSV / PORT data-connection tracking | No | `ftp`, `ftp.command`, `ftp.arg`, `ftp.req`, `ftp.rsp`, `ftp.response.code`, `ftp_data` |
| **TFTP** | RRQ/WRQ/DATA/ACK/ERROR/OACK, dynamic UDP TID sessions | N/A (UDP) | `tftp`, `tftp.opcode`, `tftp.block`, `tftp.mode`, `tftp.source_file`, `tftp.error.code` |
| **BGP** | BGP marker, OPEN, UPDATE, NOTIFICATION, KEEPALIVE, NLRI prefix | Yes (TCP) | `bgp`, `bgp.type`, `bgp.as`, `bgp.nlri`, `bgp.notification.code` |
| **LDAP** | BER header framing + reassembly, Message ID, Bind (password never shown; SASL GSS-SPNEGO / GSSAPI tokens decoded), Search (scope, RFC 4515 filter, attributes), entries with attribute values (credentials hidden), Modify / Add / ModDN / Compare / Abandon, controls, referrals, results with result-code names, Extended / StartTLS (TLS follows), ports 389 / 636 / 3268 / 3269 | Yes (TCP) | `ldap`, `ldap.message_id`, `ldap.protocol_op`, `ldap.name`, `ldap.result_code`, `ldap.extended_name` |
| **Kerberos** | RFC 4120 tags per message type, AS/TGS/AP REQ/REP, KRB-ERROR names, PA-DATA types (PA-TGS-REQ / ENC-TIMESTAMP / ETYPE-INFO2 / PAC-REQUEST values), KRB-SAFE / PRIV / CRED, EncryptedData marked encrypted, KDC / AP option names, principal / realm, UDP + TCP record mark; the SPNEGO / GSS-API blob decoder (`spnego.cpp`) reuses it for SMB2 and LDAP SASL | Yes (TCP) | `kerberos`, `kerberos.msg_type`, `kerberos.error_code`, `kerberos.realm`, `kerberos.cname`, `kerberos.sname` |
| **SMB2 / SMB3** | NBSS, compound / async headers with credits, Negotiate (dialects, 3.1.1 contexts), Session Setup through SPNEGO (NTLMSSP decoded, Kerberos AP-REQ / AP-REP), Tree Connect, Create (contexts), Close, Flush, Read / Write, IOCTL (FSCTL names), Query Directory, Change Notify, Query / Set Info (common MS-FSCC classes), session table (TreeId to share, FileId to file name, request / response matching by MessageId, related compounds, named pipes), NT status (MS-ERREF), Transform = encrypted label, SMB1 negotiate recognised | Yes (TCP) | `smb2`, `smb2.cmd`, `smb2.nt_status`, `smb2.flags.response`, `smb2.flags.signed`, `smb2.encrypted`, `smb2.dialect`, `smb2.tree`, `smb2.filename`, `smb2.user`, `smb2.file`, `smb2.pipe` |
| **DCE/RPC** | CO (version 5) and CL (version 4) PDUs in the sender's byte order, every Bind context + interface name, Bind_ack / nak, Request opnum + object UUID, Fault status, context id → interface and Response → Request through the session table, fragment reassembly, authentication verifier labelled (stub data at packet privacy sealed), endpoint mapper towers and a port map for later connections, PDUs in SMB2 named pipes | Yes (TCP, UDP; announced ports; SMB2 pipes) | `dcerpc`, `dcerpc.pkt_type`, `dcerpc.opnum`, `dcerpc.cn_call_id`, `dcerpc.if_uuid`, `dcerpc.auth_level`, `dcerpc.auth_service`, `dcerpc.sealed`, `dcerpc.fragment`, `dcerpc.reassembled` |
| **NFS / ONC RPC** | TCP record-fragment reassembly, XID call/reply matching, retransmissions, AUTH_SYS; NFSv3 call arguments/results; NFSv4.0/4.1 COMPOUND operation sequences and matched results (bounded, partial pNFS); Portmap/rpcbind announced ports and Mount results | Yes (TCP) | `rpc`, `rpc.xid`, `rpc.msgtyp`, `rpc.program`, `rpc.programversion`, `rpc.procedure`, `rpc.state_accept`, `rpc.reply_denied`, `rpc.matched`, `rpc.retransmission`, `rpc.duplicate_reply`, `rpc.fragment`, `rpc.reassembled`, `nfs`, `nfs.proc`, `nfs.version`, `nfs.name`, `nfs.status`, `nfs.operations`, `portmap.proc`, `mount.path` |
| **PostgreSQL** | Startup / SSLRequest (+ TLS follow) / Cancel, typed messages by direction, queries, authentication types, ErrorResponse SQLSTATE | Yes (TCP) | `pgsql`, `pgsql.type`, `pgsql.query`, `pgsql.user`, `pgsql.code`, `pgsql.ssl_request` |
| **MySQL** | Direction-aware: greeting, login (no password hash), SSLRequest (+ TLS follow), commands, OK / ERR / EOF, result set packets | Yes (TCP) | `mysql`, `mysql.command`, `mysql.query`, `mysql.error_code`, `mysql.version`, `mysql.user`, `mysql.packet_number`, `mysql.from_server`, `mysql.ssl_request` |
| **TDS (SQL Server)**| Pre-Login options, wrapped TLS handshake, Login7 (password masked), SQL Batch, RPC, response tokens (ERROR number) | Yes (TCP) | `tds`, `tds.type`, `tds.status`, `tds.spid`, `tds.query`, `tds.user`, `tds.encryption`, `tds.error_number` |
| **SIP / SDP** | Request/status line (validated), CSeq, Call-ID, From, To (case-insensitive, compact forms), SDP lines | Yes (TCP, Content-Length bounded to 64 KiB) / UDP | none yet (see KNOWN_ISSUES) |
| **RTP / RTCP** | RTP v2 fixed header (PT, Seq, Timestamp, SSRC), RTCP common header + SSRC | N/A (UDP, Decode As only) | none yet (see KNOWN_ISSUES) |
| **Modbus/TCP** | MBAP header (Transaction ID, Unit ID), function and exception codes | Yes (TCP) | none yet (see KNOWN_ISSUES) |
| **DNP3** | Link 0x0564 start, length, control, source/destination, first application function code; link header and data block CRC-16 verified | Yes (TCP) / UDP | `dnp3`, `dnp3.checksum.status`, `dnp3.header.checksum.status`, `dnp3.data.checksum.status` |
| **USB** | Linux & USBPcap URB/IRP: request vs completion, IN/OUT, transfer types, setup packet, descriptors (GET_DESCRIPTOR completions) | N/A (USB) | `usb`, `usb.device`, `usb.endpoint` |
| **Bluetooth** | HCI H4 and Linux Monitor, L2CAP header, ATT opcode/MTU/handle; host / controller / ACL handle addresses | N/A (BT) | `bt.handle`, `bt.addr` |

---

## 6. Known Limitations

- **Decryption:** TLS/DTLS decryption relies on provided session keys (keylog files) or pcapng Decryption Secrets Blocks (DSB); live dynamic key extraction from memory is not supported.
- **Windows Platform:** While build targets and CI matrix for Windows are configured, native hardware testing has not been performed locally.
- **Memory safety:** the test suite includes truncation and seeded byte-mutation sweeps for many protocols that assert every field offset stays inside the frame, and the whole suite is run under AddressSanitizer and UndefinedBehaviorSanitizer (`-DIMSHARK_SANITIZE=ON`, also what CI builds on Linux and macOS). This is evidence for the inputs the tests generate, not a proof for every dissector: older dissectors have no sweep of their own, and there is no separate fuzzing harness.
- **Real captures:** many advanced protocols have no real capture in the corpus manifest. USB, Bluetooth monitor and 802.15.4 decoding still need independent verification against real captures.
- **Encrypted content:** ESP (unless the optional ESP-NULL heuristic recognises an unencrypted payload), IKEv2 SK / SKF payloads, IKEv1 messages with the encryption flag and SMB2 transform (encrypted) messages are labelled, not decoded. TLS that starts inside LDAP (StartTLS), PostgreSQL, MySQL or TDS is dissected as TLS from the upgrade on; it can be decrypted with a key log except TLS-in-TDS, whose handshake is wrapped in Pre-Login packets and is not handed to the TLS dissector. TLS/DTLS decryption needs an OpenSSL 3 build and supplied keys.
