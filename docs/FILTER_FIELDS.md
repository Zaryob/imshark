# Display Filter Field Reference

<!-- Generated from the field modules (core/src/dissect/*_fields.cpp) by the test Docs.FilterReferenceIsGeneratedFromTheFieldTable.
     Do not edit by hand: run the tests with IMSHARK_UPDATE_DOCS=1 to rewrite it. -->

Every field the display filter knows (the same list as the `?` button next to the filter bar). A field of type
`protocol` is true when the packet contains the protocol; the other types are compared with the operators described
in the [User Guide](USER_GUIDE.md#display-filters). Names are lower case.

| Field | Type | Description |
|---|---|---|
| `_ws.col.info` | string | Info column |
| `_ws.col.protocol` | string | Protocol column |
| `ah` | boolean | IPsec Authentication Header (IPv4 or IPv6) |
| `ah.sequence` | unsigned | AH Sequence Number |
| `ah.spi` | unsigned | AH Security Parameters Index (SPI) |
| `arp` | boolean | ARP / RARP |
| `bgp` | boolean | BGP |
| `bgp.as` | unsigned | BGP Autonomous System number |
| `bgp.nlri` | string | BGP Network Layer Reachability Information prefix |
| `bgp.notification.code` | unsigned | BGP notification error code |
| `bgp.type` | unsigned | BGP message type (1 = OPEN, 2 = UPDATE, 3 = NOTIFICATION, 4 = KEEPALIVE, 5 = ROUTE-REFRESH) |
| `bt.addr` | string | Bluetooth source or destination: host, controller (hciN), a BD_ADDR, or a connection handle |
| `bt.bd_addr` | string | Bluetooth BD_ADDR of the remote device of an ACL link (aa:bb:cc:dd:ee:ff; only when an HCI connection event in the capture named the handle) |
| `bt.handle` | string | Bluetooth ACL connection handle (0x0040 form) |
| `dcerpc` | boolean | DCE/RPC |
| `dcerpc.auth_level` | unsigned | DCE/RPC authentication level of the PDU's verifier (1 none ... 5 packet integrity, 6 packet privacy) |
| `dcerpc.auth_service` | string | DCE/RPC authentication service of the PDU's verifier (NTLMSSP, Kerberos, SPNEGO, ...) |
| `dcerpc.cn_call_id` | unsigned | DCE/RPC call id of a connection-oriented PDU (not kept for a PDU inside an SMB2 packet) |
| `dcerpc.fragment` | boolean | DCE/RPC PDU is one fragment of a call split over several PDUs |
| `dcerpc.if_uuid` | string | DCE/RPC interface UUID: of the first presentation context of a Bind / Alter_context, of the context a Request / Response used |
| `dcerpc.opnum` | unsigned | DCE/RPC operation number of a Request |
| `dcerpc.pkt_type` | unsigned | DCE/RPC PDU type (0 Request, 2 Response, 3 Fault, 11 Bind, 12 Bind_ack); also of a PDU in the first SMB2 command of a packet (named pipe) |
| `dcerpc.reassembled` | boolean | DCE/RPC PDU completes a call that was split into fragments |
| `dcerpc.sealed` | boolean | DCE/RPC stub data is sealed (packet privacy): labelled, not interpreted |
| `dhcp` | boolean | DHCP |
| `dhcp.option.hostname` | string | DHCP host name option |
| `dhcp.type` | unsigned | DHCP message type (1 = Discover, 2 = Offer, 3 = Request, 5 = ACK ...) |
| `dnp3` | boolean | Distributed Network Protocol 3.0 |
| `dnp3.checksum.status` | unsigned | DNP3 CRC-16 of the link header and all data blocks: 0 = bad (any), 1 = good, 2 = unverified (block cut by the capture) |
| `dnp3.data.checksum.status` | unsigned | DNP3 CRC-16 of all user data blocks: 0 = bad (any block), 1 = good, 2 = unverified, 3 = not present (no user data) |
| `dnp3.header.checksum.status` | unsigned | DNP3 link header CRC-16: 0 = bad, 1 = good |
| `dns` | boolean | DNS |
| `dns.flags.rcode` | unsigned | DNS reply code (0 = no error, 3 = NXDOMAIN ...) |
| `dns.flags.response` | boolean | DNS message is a response |
| `dns.flags.truncated` | boolean | DNS message is truncated |
| `dns.qry.name` | string | Name of the first DNS question |
| `dns.qry.type` | unsigned | Type of the first DNS question (1 = A, 28 = AAAA, 15 = MX ...) |
| `dtls` | boolean | Datagram TLS (DTLS) |
| `dtls.decrypted` | boolean | The packet carries DTLS records that were decrypted with a key log |
| `dtls.decryption_status` | string | What became of the protected DTLS records of the packet: decrypted, tag_failure (wrong key), no_key, unsupported_suite, malformed, unavailable (no OpenSSL), no_handshake, state_lost |
| `dtls.handshake.certificate_subject` | string | Common name of the first certificate in a Certificate message |
| `dtls.handshake.cookie_length` | unsigned | Length of the cookie of a ClientHello or HelloVerifyRequest |
| `dtls.handshake.extensions_server_name` | string | Server name indication (SNI) of a ClientHello |
| `dtls.handshake.type` | unsigned | First handshake message type (1 = ClientHello, 2 = ServerHello, 3 = HelloVerifyRequest ...) |
| `dtls.record.content_type` | unsigned | Content type of the first DTLS record (22 = handshake, 23 = application data) |
| `dtls.record.epoch` | unsigned | Epoch of the first DTLS record |
| `dtls.record.sequence_number` | unsigned | 48 bit sequence number of the first DTLS record |
| `dtls.record.version` | unsigned | Version of the first DTLS record (0xfefd = DTLS 1.2, 0xfeff = 1.0; 0xfefc for a DTLS 1.3 unified header) |
| `eap` | boolean | Extensible Authentication Protocol |
| `eap.code` | unsigned | EAP code (1 = Request, 2 = Response, 3 = Success, 4 = Failure) |
| `eap.identity` | string | EAP Identity username/string |
| `eap.type` | unsigned | EAP type (1 = Identity, 13 = TLS, 25 = PEAP, 43 = FAST) |
| `eapol` | boolean | IEEE 802.1X / EAPOL packet |
| `eapol.keydes.msgnr` | unsigned | WPA 4-way handshake message number (1, 2, 3, 4) |
| `eapol.keydes.type` | unsigned | EAPOL-Key descriptor type (1 = RC4, 2 = RSN, 254 = WPA) |
| `eapol.type` | unsigned | 802.1X packet type (0 = EAP, 1 = Start, 2 = Logoff, 3 = Key) |
| `esp` | boolean | IPsec Encapsulating Security Payload |
| `esp.null` | boolean | ESP payload judged unencrypted by the ESP-NULL heuristic (a setting, off by default) |
| `esp.sequence` | unsigned | ESP Sequence Number |
| `esp.spi` | unsigned | ESP Security Parameters Index (SPI) |
| `eth` | boolean | Ethernet frame |
| `eth.addr` | string | Ethernet source or destination address (every Ethernet frame when the capture's address table is available; otherwise only frames that are not IP packets) |
| `eth.dst` | string | Ethernet destination address (every Ethernet frame when the capture's address table is available; otherwise only frames that are not IP packets) |
| `eth.len` | unsigned | IEEE 802.3 length field |
| `eth.src` | string | Ethernet source address (every Ethernet frame when the capture's address table is available; otherwise only frames that are not IP packets) |
| `eth.type` | unsigned | EtherType |
| `frame.cap_len` | unsigned | Number of bytes captured |
| `frame.comment` | boolean | The capture file has a comment for this packet (pcapng) |
| `frame.len` | unsigned | Length of the frame on the wire |
| `frame.number` | unsigned | Packet number (1-based) |
| `frame.time_delta` | float | Seconds since the previous captured packet |
| `frame.time_epoch` | float | Arrival time as UTC epoch seconds |
| `frame.time_relative` | float | Seconds since the first packet |
| `ftp` | boolean | FTP |
| `ftp.arg` | string | FTP command or response argument |
| `ftp.command` | string | FTP command name (e.g. USER, PASS, PORT, PASV, RETR) |
| `ftp.req` | boolean | FTP command/request |
| `ftp.response.code` | unsigned | FTP response code (e.g. 200, 220, 227, 230, 550) |
| `ftp.rsp` | boolean | FTP server response |
| `ftp_data` | boolean | FTP-DATA |
| `gre` | boolean | Generic Routing Encapsulation |
| `gre.flags.checksum` | boolean | GRE Checksum present flag |
| `gre.flags.key` | boolean | GRE Key present flag |
| `gre.flags.routing` | boolean | GRE Routing present flag |
| `gre.flags.sequence` | boolean | GRE Sequence Number present flag |
| `gre.key` | unsigned | GRE Key (low 16 bits) |
| `gre.proto` | unsigned | GRE Protocol Type (0x0800 = IPv4, 0x86DD = IPv6, 0x6558 = Ethernet, 0x880B = PPP) |
| `gre.sequence_number` | unsigned | GRE Sequence Number (low 16 bits) |
| `gre.version` | unsigned | GRE Version (0 = RFC 2784, 1 = Enhanced GRE/RFC 2637) |
| `http` | boolean | HTTP/1.x |
| `http.content_type` | string | HTTP response Content-Type |
| `http.host` | string | HTTP Host header |
| `http.request` | boolean | HTTP request |
| `http.request.method` | string | HTTP request method (GET, POST ...) |
| `http.request.uri` | string | HTTP request URI |
| `http.response` | boolean | HTTP response |
| `http.response.code` | unsigned | HTTP response status code |
| `http2` | boolean | HTTP/2 |
| `http2.flags` | unsigned | HTTP/2 frame flags |
| `http2.headers.method` | string | HTTP/2 request method |
| `http2.headers.path` | string | HTTP/2 request path |
| `http2.headers.status` | unsigned | HTTP/2 response status code |
| `http2.streamid` | unsigned | HTTP/2 stream identifier |
| `http2.type` | unsigned | HTTP/2 frame type (0 = DATA, 1 = HEADERS, 4 = SETTINGS ...) |
| `icmp` | boolean | ICMP |
| `icmp.checksum.status` | unsigned | ICMP checksum: 0 = bad, 1 = good, 2 = unverified |
| `icmp.code` | unsigned | ICMP message code |
| `icmp.type` | unsigned | ICMP message type |
| `icmpv6` | boolean | ICMPv6 |
| `icmpv6.checksum.status` | unsigned | ICMPv6 checksum: 0 = bad, 1 = good, 2 = unverified |
| `icmpv6.code` | unsigned | ICMPv6 message code |
| `icmpv6.type` | unsigned | ICMPv6 message type |
| `igmp` | boolean | Internet Group Management Protocol |
| `igmp.group` | string | IGMP Multicast Group Address |
| `igmp.num_records` | unsigned | Number of group records announced by an IGMPv3 Membership Report |
| `igmp.num_sources` | unsigned | Number of sources announced by an IGMPv3 Membership Query |
| `igmp.type` | unsigned | IGMP Message Type (0x11 Query, 0x12 v1 Report, 0x16 v2 Report, 0x17 Leave, 0x22 v3 Report) |
| `igmp.version` | unsigned | IGMP version implied by the message (1, 2 or 3; a query is v3 when it has at least 12 bytes, v1 when its Max Resp Code is 0) |
| `ike` | boolean | Internet Key Exchange / ISAKMP |
| `ike.exchange_type` | unsigned | IKE Exchange Type |
| `ike.fragment` | boolean | IKEv2 encrypted fragment (SKF, RFC 7383) |
| `ike.fragment.number` | unsigned | IKEv2 fragment number (SKF) |
| `ike.fragment.total` | unsigned | IKEv2 total number of fragments (SKF) |
| `ike.initiator_spi` | string | IKE Initiator SPI (0x, 16 hex digits) |
| `ike.message_id` | unsigned | IKE Message ID |
| `ike.notify.type` | unsigned | Message Type of the first unencrypted Notify payload (IKEv2 and IKEv1 registries differ) |
| `ike.responder_spi` | string | IKE Responder SPI (0x, 16 hex digits) |
| `ike.version` | unsigned | IKE Version (1 or 2) |
| `info` | string | Info column (alias of _ws.col.info) |
| `ip` | boolean | IPv4 |
| `ip.addr` | IPv4 address | IPv4 source or destination address |
| `ip.checksum.status` | unsigned | IPv4 header checksum: 0 = bad, 1 = good, 2 = unverified (offload or truncated), 3 = not present |
| `ip.dst` | IPv4 address | IPv4 destination address |
| `ip.fragment` | boolean | IPv4 fragment (part of a fragmented datagram) |
| `ip.id` | unsigned | IPv4 identification |
| `ip.proto` | unsigned | IPv4 protocol number |
| `ip.reassembled` | boolean | Last IPv4 fragment: the datagram was reassembled here |
| `ip.src` | IPv4 address | IPv4 source address |
| `ip.ttl` | unsigned | IPv4 time to live |
| `ip.version` | unsigned | IPv4 version |
| `ipip` | boolean | IP-in-IP tunnel (protocol 4 or 41) |
| `ipv6` | boolean | IPv6 |
| `ipv6.addr` | IPv6 address | IPv6 source or destination address |
| `ipv6.dst` | IPv6 address | IPv6 destination address |
| `ipv6.fragment` | boolean | IPv6 fragment (part of a fragmented datagram) |
| `ipv6.fragment.id` | unsigned | IPv6 Fragment Header identification |
| `ipv6.hlim` | unsigned | IPv6 hop limit |
| `ipv6.nxt` | unsigned | IPv6 next header (after extension headers) |
| `ipv6.reassembled` | boolean | Last IPv6 fragment: the datagram was reassembled here |
| `ipv6.src` | IPv6 address | IPv6 source address |
| `kerberos` | boolean | Kerberos |
| `kerberos.cname` | string | Kerberos client principal name |
| `kerberos.error_code` | unsigned | Kerberos KRB-ERROR error code (25 = KDC_ERR_PREAUTH_REQUIRED) |
| `kerberos.msg_type` | unsigned | Kerberos message type (10 AS-REQ, 11 AS-REP, 12 TGS-REQ, 13 TGS-REP, 14 AP-REQ, 15 AP-REP, 30 KRB-ERROR) |
| `kerberos.realm` | string | Kerberos realm |
| `kerberos.sname` | string | Kerberos service principal name |
| `lacp` | boolean | Link Aggregation Control Protocol |
| `lacp.actor.port` | unsigned | LACP Actor Port number |
| `lacp.actor.state` | unsigned | LACP Actor State byte |
| `lacp.actor.state.activity` | boolean | LACP Actor Activity bit |
| `lacp.actor.state.collecting` | boolean | LACP Actor Collecting bit |
| `lacp.actor.state.distributing` | boolean | LACP Actor Distributing bit |
| `lacp.actor.state.synchronization` | boolean | LACP Actor Synchronization bit |
| `lacp.actor.system` | string | LACP Actor System ID (MAC) |
| `lacp.partner.port` | unsigned | LACP Partner Port number |
| `lacp.partner.state` | unsigned | LACP Partner State byte |
| `lacp.partner.system` | string | LACP Partner System ID (MAC) |
| `ldap` | boolean | Lightweight Directory Access Protocol |
| `ldap.extended_name` | string | LDAP extended operation OID (1.3.6.1.4.1.1466.20037 is StartTLS) |
| `ldap.message_id` | unsigned | LDAP Message ID |
| `ldap.name` | string | LDAP Distinguished Name / Target Object |
| `ldap.protocol_op` | unsigned | LDAP Protocol Operation (Application tag) |
| `ldap.result_code` | unsigned | LDAP result code of a response (0 success, 49 invalidCredentials, ...) |
| `llc` | boolean | IEEE 802.2 Logical-Link Control |
| `llc.control` | unsigned | LLC Control Field |
| `llc.dsap` | unsigned | LLC Destination Service Access Point (DSAP) |
| `llc.ssap` | unsigned | LLC Source Service Access Point (SSAP) |
| `lldp` | boolean | Link Layer Discovery Protocol |
| `lldp.capabilities` | unsigned | LLDP System Capabilities (enabled bits) |
| `lldp.chassis_id` | string | LLDP Chassis ID |
| `lldp.port_id` | string | LLDP Port ID |
| `lldp.ttl` | unsigned | LLDP Time To Live in seconds |
| `mac_control` | boolean | Ethernet MAC Control |
| `mac_control.opcode` | unsigned | MAC Control opcode (0x0001 PAUSE, 0x0101 PFC) |
| `malformed` | boolean | Packet that could not be fully decoded |
| `mdns` | boolean | Multicast DNS |
| `mount.path` | string | Mount directory path of a MNT / UMNT call |
| `mpls` | boolean | MultiProtocol Label Switching |
| `mpls.bottom_of_stack` | boolean | MPLS Bottom of Stack flag (outermost label) |
| `mpls.exp` | unsigned | MPLS Experimental (TC) Bits |
| `mpls.label` | unsigned | MPLS Label Value (outermost label) |
| `mpls.label1` | unsigned | MPLS Label Value (second label in the stack) |
| `mpls.ttl` | unsigned | MPLS Time To Live |
| `mysql` | boolean | MySQL client/server protocol |
| `mysql.command` | unsigned | MySQL command of a client packet (3 COM_QUERY, 2 COM_INIT_DB, 1 COM_QUIT, 22 COM_STMT_PREPARE, ...) |
| `mysql.error_code` | unsigned | MySQL error code of an ERR packet |
| `mysql.from_server` | boolean | MySQL packet sent by the server |
| `mysql.packet_number` | unsigned | MySQL packet (sequence) number |
| `mysql.query` | string | MySQL SQL text of COM_QUERY / COM_STMT_PREPARE (or the schema of COM_INIT_DB) |
| `mysql.ssl_request` | boolean | MySQL SSL request (TLS handshake follows) |
| `mysql.user` | string | MySQL user name of the login request |
| `mysql.version` | string | MySQL server version of the initial handshake |
| `nfs` | boolean | Network File System call or matched reply |
| `nfs.name` | string | NFS file name of a LOOKUP / CREATE / MKDIR / REMOVE / RMDIR call |
| `nfs.proc` | unsigned | NFS procedure of a call or matched reply (v3: 1 GETATTR, 3 LOOKUP, 6 READ, 7 WRITE; v4: 1 COMPOUND) |
| `nfs.version` | unsigned | NFS protocol version of a call or matched reply |
| `ntp` | boolean | NTP |
| `ntp.ctrl.opcode` | unsigned | Opcode of an NTP control message (2 = read variables) |
| `ntp.mode` | unsigned | NTP mode (3 = client, 4 = server) |
| `ntp.priv.reqcode` | unsigned | Request code of an NTP private (mode 7) message |
| `ntp.stratum` | unsigned | NTP stratum |
| `ntp.version` | unsigned | NTP version |
| `ospf` | boolean | Open Shortest Path First |
| `ospf.area_id` | string | OSPF Area ID |
| `ospf.auth.type` | unsigned | OSPFv2 authentication type (0 none, 1 simple password, 2 cryptographic) |
| `ospf.instance_id` | unsigned | OSPFv3 Instance ID (RFC 5340 A.3.1) |
| `ospf.lsa.checksum.status` | unsigned | OSPF LSA Fletcher checksum (RFC 2328 12.1.7, RFC 5340 A.4.2) of the LSAs in a DD, LSU or LSAck: 0 = bad (any), 1 = good, 2 = unverified (headers only, or cut off); absent without LSAs |
| `ospf.lsa.count` | unsigned | Number of LSAs found in an OSPF Database Description or Link State Acknowledgment (headers) or Link State Update |
| `ospf.router_id` | string | OSPF Router ID |
| `ospf.type` | unsigned | OSPF Packet Type (1=Hello, 2=DD, 3=LSR, 4=LSU, 5=LSAck) |
| `ospf.version` | unsigned | OSPF Version (2 or 3) |
| `pause` | boolean | Ethernet PAUSE frame |
| `pause.time` | unsigned | PAUSE time (units of 512 bit times) |
| `pfc` | boolean | Priority Flow Control frame |
| `pfc.class_enable` | unsigned | PFC Class Enable Vector |
| `pgsql` | boolean | PostgreSQL frontend/backend protocol |
| `pgsql.code` | string | PostgreSQL SQLSTATE of an ErrorResponse / NoticeResponse |
| `pgsql.query` | string | PostgreSQL SQL text of a SimpleQuery or Parse message |
| `pgsql.ssl_request` | boolean | PostgreSQL SSLRequest |
| `pgsql.type` | string | PostgreSQL message type letter (Q SimpleQuery, P Parse, R Authentication, Z ReadyForQuery, ...) |
| `pgsql.user` | string | PostgreSQL user of a StartupMessage |
| `portmap.proc` | unsigned | Portmap procedure of a call or matched reply (3 GETPORT) |
| `ppi.dlt` | unsigned | PPI encapsulated Data Link Type |
| `ppp` | boolean | Point-to-Point Protocol |
| `ppp.ipcp.code` | unsigned | IPCP Code |
| `ppp.lcp.code` | unsigned | LCP Code (1 = Config-Req, 2 = Config-Ack, etc.) |
| `ppp.protocol` | unsigned | PPP Protocol ID (0x0021 = IPv4, 0x0057 = IPv6, 0xc021 = LCP, 0x8021 = IPCP) |
| `pppoe` | boolean | PPP-over-Ethernet (Discovery or Session) |
| `pppoe.ac_name` | string | PPPoE Access Concentrator (AC) Name tag |
| `pppoe.code` | unsigned | PPPoE Code (0x00 = Session, 0x09 = PADI, 0x07 = PADO, 0x19 = PADR, 0x65 = PADS, 0xa7 = PADT) |
| `pppoe.service_name` | string | PPPoE Service-Name tag |
| `pppoe.session_id` | unsigned | PPPoE Session ID |
| `pppoed` | boolean | PPPoE Discovery Stage |
| `pppoes` | boolean | PPPoE Session Stage |
| `protocol` | string | Protocol column (alias of _ws.col.protocol) |
| `radiotap.channel.freq` | unsigned | Radiotap/PPI channel frequency in MHz |
| `radiotap.datarate` | float | Radiotap/PPI data rate in Mb/s |
| `radiotap.dbm_antsignal` | float | Radiotap/PPI antenna signal in dBm |
| `rpc` | boolean | ONC RPC (also NFS, Portmap and Mount) |
| `rpc.duplicate_reply` | boolean | ONC RPC second reply to the same call |
| `rpc.fragment` | boolean | ONC RPC record fragment that is not the last one of its record |
| `rpc.matched` | boolean | ONC RPC reply whose call was seen earlier in the capture (xid, addresses and ports agree) |
| `rpc.msgtyp` | unsigned | ONC RPC message type (0 call, 1 reply) |
| `rpc.procedure` | unsigned | ONC RPC procedure number of a call, or of the call a matched reply answers |
| `rpc.program` | unsigned | ONC RPC program number of a call, or of the call a matched reply answers (100003 NFS, 100000 Portmap, 100005 Mount) |
| `rpc.programversion` | unsigned | ONC RPC program version of a call, or of the call a matched reply answers |
| `rpc.reassembled` | boolean | ONC RPC message joined from the several fragments of its TCP record (shown on the last fragment) |
| `rpc.reply_denied` | boolean | ONC RPC reply that was denied (RPC_MISMATCH or AUTH_ERROR) |
| `rpc.retransmission` | boolean | ONC RPC call seen again (same xid, program, version and procedure) |
| `rpc.state_accept` | unsigned | ONC RPC accept status of an accepted reply (0 SUCCESS, 1 PROG_UNAVAIL, 2 PROG_MISMATCH, 3 PROC_UNAVAIL ...) |
| `rpc.xid` | unsigned | ONC RPC transaction id |
| `sctp` | boolean | Stream Control Transmission Protocol |
| `sctp.checksum.status` | unsigned | SCTP CRC-32C: 0 = bad, 1 = good, 2 = unverified, 3 = not present |
| `sctp.chunk_type` | unsigned | SCTP Chunk Type (of the first chunk) |
| `sctp.data` | boolean | SCTP packet with a DATA or I-DATA chunk |
| `sctp.data.fragment` | boolean | The first data chunk carries only part of a user message |
| `sctp.data.idata` | boolean | The first data chunk is an I-DATA chunk |
| `sctp.data.ppid` | unsigned | Payload protocol identifier of the first DATA / I-DATA chunk (of the whole message when it was reassembled) |
| `sctp.data.retransmission` | boolean | The first data chunk is a fragment seen before |
| `sctp.data.sid` | unsigned | Stream identifier of the first DATA / I-DATA chunk |
| `sctp.data.ssn` | unsigned | Stream sequence number (DATA) or message identifier (I-DATA) of the first DATA / I-DATA chunk |
| `sctp.data.tsn` | unsigned | TSN of the first DATA / I-DATA chunk |
| `sctp.data.unordered` | boolean | The first data chunk has the U (unordered) flag |
| `sctp.dstport` | unsigned | SCTP destination port |
| `sctp.port` | unsigned | SCTP source or destination port |
| `sctp.reassembled` | boolean | This packet's first data chunk completed a user message (reassembled SCTP message) |
| `sctp.srcport` | unsigned | SCTP source port |
| `sctp.vtag` | unsigned | SCTP Verification Tag |
| `smb2` | boolean | SMB2 / SMB3 |
| `smb2.cmd` | unsigned | SMB2 command of the first message in the packet (0 Negotiate, 1 Session Setup, 3 Tree Connect, 5 Create, 8 Read, 9 Write) |
| `smb2.dialect` | unsigned | SMB2 dialect revision chosen by a Negotiate response (0x0311 = SMB 3.1.1) |
| `smb2.encrypted` | boolean | SMB3 message in a Transform header (encrypted, content not shown) |
| `smb2.file` | string | SMB2 file the first command works on: the Create name, or the name behind its FileId / matched request (session table) |
| `smb2.filename` | string | SMB2 file name of a Create request |
| `smb2.flags.response` | boolean | SMB2 response flag of the first message |
| `smb2.flags.signed` | boolean | SMB2 signed flag of the first message |
| `smb2.nt_status` | unsigned | SMB2 NT status of a response (first message) |
| `smb2.pipe` | boolean | SMB2 first command works on a named pipe (a file of an IPC$ share, or the IPC$ tree itself) |
| `smb2.tree` | string | SMB2 share path of a Tree Connect request |
| `smb2.user` | string | SMB2 user of an NTLMSSP authenticate message (domain\user) |
| `smtp` | boolean | SMTP |
| `smtp.command` | string | SMTP command name (e.g. EHLO, MAIL FROM, RCPT TO, DATA) |
| `smtp.param` | string | SMTP command or response parameter |
| `smtp.req` | boolean | SMTP command/request |
| `smtp.response.code` | unsigned | SMTP response code (e.g. 220, 250, 354, 550) |
| `smtp.rsp` | boolean | SMTP server response |
| `snap` | boolean | Subnetwork Access Protocol (SNAP) |
| `snap.oui` | unsigned | SNAP Organizationally Unique Identifier (OUI) |
| `snap.type` | unsigned | SNAP Protocol ID / EtherType |
| `snmp` | boolean | SNMP |
| `snmp.community` | string | SNMP community string or v3 user name |
| `snmp.error_status` | unsigned | SNMP error-status code |
| `snmp.oid` | string | SNMP first variable binding OID |
| `snmp.pdu_type` | unsigned | SNMP PDU type (0 = GetRequest, 1 = GetNextRequest, 2 = Response ...) |
| `snmp.request_id` | unsigned | SNMP request ID |
| `snmp.version` | unsigned | SNMP version (0 = v1, 1 = v2c, 3 = v3) |
| `ssh` | boolean | SSH |
| `ssh.encrypted` | boolean | SSH encrypted packet payload |
| `ssh.encryption_algorithm` | string | SSH client-to-server encryption algorithm |
| `ssh.kex_algorithm` | string | SSH key exchange algorithm |
| `ssh.message_code` | unsigned | SSH packet message code (e.g. 20 = KEXINIT, 21 = NEWKEYS) |
| `ssh.protocol` | string | SSH protocol version banner |
| `stp` | boolean | Spanning Tree Protocol (STP / RSTP / MSTP) |
| `stp.bpdu.type` | unsigned | STP BPDU Type (0x00 = Config, 0x02 = RST, 0x80 = TCN) |
| `stp.bridge.id` | string | STP Bridge Identifier |
| `stp.flags` | unsigned | STP BPDU Flags byte |
| `stp.flags.agreement` | boolean | STP Agreement flag |
| `stp.flags.forwarding` | boolean | STP Forwarding flag |
| `stp.flags.learning` | boolean | STP Learning flag |
| `stp.flags.port_role` | unsigned | STP Port Role (1 = Alternate/Backup, 2 = Root, 3 = Designated) |
| `stp.flags.proposal` | boolean | STP Proposal flag |
| `stp.flags.tc` | boolean | STP Topology Change flag |
| `stp.flags.tc_ack` | boolean | STP Topology Change Acknowledgment flag |
| `stp.port` | unsigned | STP Port Identifier |
| `stp.protocol` | unsigned | STP Protocol Identifier |
| `stp.root.cost` | unsigned | STP Root Path Cost |
| `stp.root.id` | string | STP Root Identifier |
| `stp.version` | unsigned | STP Protocol Version Identifier (0 = STP, 2 = RSTP, 3 = MSTP) |
| `tcp` | boolean | TCP |
| `tcp.ack` | unsigned | TCP relative acknowledgment number |
| `tcp.analysis.duplicate_ack` | boolean | Duplicate acknowledgment |
| `tcp.analysis.duplicate_ack_num` | unsigned | Number of the duplicate ACK (#n) |
| `tcp.analysis.flags` | boolean | Any TCP analysis note (retransmission, dup ACK, ...) |
| `tcp.analysis.keep_alive` | boolean | TCP keep-alive |
| `tcp.analysis.lost_segment` | boolean | A previous TCP segment was not captured |
| `tcp.analysis.out_of_order` | boolean | TCP segment arrived out of order |
| `tcp.analysis.retransmission` | boolean | TCP segment repeats data that was already seen |
| `tcp.analysis.window_update` | boolean | TCP window update |
| `tcp.analysis.zero_window` | boolean | Zero receive window advertised |
| `tcp.checksum.status` | unsigned | TCP checksum: 0 = bad, 1 = good, 2 = unverified (offload or truncated) |
| `tcp.dstport` | unsigned | TCP destination port |
| `tcp.flags` | unsigned | TCP flag byte |
| `tcp.flags.ack` | boolean | TCP ACK flag |
| `tcp.flags.cwr` | boolean | TCP CWR flag |
| `tcp.flags.ece` | boolean | TCP ECE flag |
| `tcp.flags.fin` | boolean | TCP FIN flag |
| `tcp.flags.push` | boolean | TCP PSH flag |
| `tcp.flags.rst` | boolean | TCP RST flag |
| `tcp.flags.syn` | boolean | TCP SYN flag |
| `tcp.flags.urg` | boolean | TCP URG flag |
| `tcp.len` | unsigned | TCP payload length |
| `tcp.port` | unsigned | TCP source or destination port |
| `tcp.reassembled` | boolean | Packet that completes a reassembled TCP message |
| `tcp.reassembled.length` | unsigned | Length of the reassembled TCP message |
| `tcp.reassembled_in` | unsigned | Number of the packet that completes the message this segment belongs to |
| `tcp.segment` | boolean | Segment of a TCP message that is reassembled in a later packet |
| `tcp.seq` | unsigned | TCP relative sequence number |
| `tcp.srcport` | unsigned | TCP source port |
| `tds` | boolean | Tabular Data Stream (SQL Server) |
| `tds.encryption` | unsigned | TDS Pre-Login ENCRYPTION option (0 OFF, 1 ON, 2 NOT_SUP, 3 REQ) |
| `tds.error_number` | unsigned | TDS ERROR token number (18456 = login failed) |
| `tds.query` | string | TDS SQL Batch text or RPC procedure name |
| `tds.spid` | unsigned | TDS server process id of the packet header |
| `tds.status` | unsigned | TDS status byte (bit 0 = end of message) |
| `tds.type` | unsigned | TDS packet type (1 SQL Batch, 3 RPC, 4 Tabular Response, 16 Login7, 18 Pre-Login) |
| `tds.user` | string | TDS Login7 user name |
| `telnet` | boolean | Telnet |
| `telnet.cmd` | unsigned | Telnet command (251 = WILL, 252 = WONT, 253 = DO, 254 = DONT, 250 = SB...) |
| `telnet.data` | string | Telnet text data or command summary |
| `telnet.subcmd` | unsigned | Telnet option code (1 = Echo, 3 = Suppress Go Ahead, 24 = Terminal Type, 31 = NAWS...) |
| `tftp` | boolean | TFTP |
| `tftp.block` | unsigned | TFTP block number |
| `tftp.error.code` | unsigned | TFTP error code |
| `tftp.mode` | string | TFTP transfer mode (e.g. netascii, octet) |
| `tftp.opcode` | unsigned | TFTP opcode (1 = RRQ, 2 = WRQ, 3 = DATA, 4 = ACK, 5 = ERROR, 6 = OACK) |
| `tftp.source_file` | string | TFTP filename |
| `tls` | boolean | TLS / SSL (also HTTP packets that were decrypted from TLS) |
| `tls.decrypted` | boolean | The packet carries TLS records that were decrypted with a key log |
| `tls.decryption_status` | string | What became of the protected TLS records of the packet: decrypted, tag_failure (wrong key), no_key, unsupported_suite, malformed, unavailable (no OpenSSL), capture_gap, no_handshake, early_data, state_lost |
| `tls.handshake.certificate_subject` | string | Common name of the first certificate in a Certificate message |
| `tls.handshake.extensions_server_name` | string | Server name indication (SNI) of a ClientHello |
| `tls.handshake.type` | unsigned | First handshake message type (1 = ClientHello, 2 = ServerHello ...) |
| `tls.record.content_type` | unsigned | Content type of the first TLS record (22 = handshake, 23 = application data) |
| `tls.record.version` | unsigned | Version of the first TLS record (0x0303 = TLS 1.2) |
| `udp` | boolean | UDP |
| `udp.checksum.status` | unsigned | UDP checksum: 0 = bad, 1 = good, 2 = unverified, 3 = not present (zero over IPv4) |
| `udp.dstport` | unsigned | UDP destination port |
| `udp.port` | unsigned | UDP source or destination port |
| `udp.srcport` | unsigned | UDP source port |
| `udplite` | boolean | Lightweight User Datagram Protocol |
| `usb` | boolean | USB packet |
| `usb.device` | string | USB device address (bus.device) |
| `usb.endpoint` | unsigned | USB endpoint address of the transfer (bit 7 set = IN, e.g. 0x81 is endpoint 1 IN) |
| `vlan` | boolean | 802.1Q VLAN tagged |
| `vlan.id` | unsigned | VLAN ID (outermost two tags) |
| `wlan` | boolean | IEEE 802.11 wireless frame |
| `wlan.bssid` | string | 802.11 BSSID MAC address |
| `wlan.da` | string | 802.11 Destination MAC address |
| `wlan.fc.fromds` | unsigned | 802.11 Frame Control From DS bit |
| `wlan.fc.protected` | unsigned | 802.11 Frame Control protected (encrypted) bit |
| `wlan.fc.retry` | unsigned | 802.11 Frame Control retry bit |
| `wlan.fc.subtype` | unsigned | 802.11 Frame Control subtype |
| `wlan.fc.tods` | unsigned | 802.11 Frame Control To DS bit |
| `wlan.fc.type` | unsigned | 802.11 Frame Control type (0 = Management, 1 = Control, 2 = Data, 3 = Extension) |
| `wlan.ra` | string | 802.11 Receiver MAC address |
| `wlan.sa` | string | 802.11 Source MAC address |
| `wlan.seq` | unsigned | 802.11 sequence number |
| `wlan.ssid` | string | 802.11 SSID |
| `wlan.ta` | string | 802.11 Transmitter MAC address |

409 fields.
