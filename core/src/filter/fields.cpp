#include "fields.h"

#include <algorithm>
#include <cstdlib>
#include <deque>
#include <mutex>

#include <cstdio>

#include "field_helpers.h"
#include "field_modules.h"

namespace filter {
    namespace {
        using namespace fh;
        using packet::PacketInfo;

        // The rows that are not in a field module yet (they move out protocol by protocol).
        std::vector<FieldDef> legacyRows() {
            std::vector<FieldDef> t = {
                // ---- frame
                // ---- link layer
                // ---- network layer
                // ---- transport layer
                {"dnp3", FieldType::Boolean, proto<[](const PacketInfo &p) { return p.protocol == "DNP3"; }>, "Distributed Network Protocol 3.0"},
                {"dnp3.checksum.status", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (p.protocol == "DNP3") o.addU(checksumStatusNumber(dnp3CrcState(p, true, true))); }, "DNP3 CRC-16 of the link header and all data blocks: 0 = bad (any), 1 = good, 2 = unverified (block cut by the capture)"},
                {"dnp3.header.checksum.status", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (p.protocol == "DNP3") o.addU(checksumStatusNumber(dnp3CrcState(p, true, false))); }, "DNP3 link header CRC-16: 0 = bad, 1 = good"},
                {"dnp3.data.checksum.status", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (p.protocol == "DNP3") o.addU(checksumStatusNumber(dnp3CrcState(p, false, true))); }, "DNP3 CRC-16 of all user data blocks: 0 = bad (any block), 1 = good, 2 = unverified, 3 = not present (no user data)"},
                {"ospf", FieldType::Boolean, proto<[](const PacketInfo &p) { return p.protocol == "OSPF" || p.ip_protocol == 89; }>, "Open Shortest Path First"},
                {"ospf.version", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (p.protocol == "OSPF") o.addU(p.app_code); }, "OSPF Version (2 or 3)"},
                {"ospf.type", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (p.protocol == "OSPF") o.addU(p.app_type); }, "OSPF Packet Type (1=Hello, 2=DD, 3=LSR, 4=LSU, 5=LSAck)"},
                {"ospf.lsa.checksum.status", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (p.protocol == "OSPF" && (p.app_flags & 3) != dissect::kChecksumNone) o.addU(checksumStatusNumber(static_cast<uint8_t>(p.app_flags & 3))); }, "OSPFv2 LSA Fletcher checksum (RFC 2328 12.1.7) of the LSAs in a DD, LSU or LSAck: 0 = bad (any), 1 = good, 2 = unverified (headers only, or cut off); absent without LSAs"},
                {"ospf.router_id", FieldType::String, [](const PacketInfo &p, const Context &, Values &o) { if (p.protocol == "OSPF" && !p.app_text.empty()) o.addS(p.app_text); }, "OSPF Router ID"},
                {"ospf.area_id", FieldType::String, [](const PacketInfo &p, const Context &, Values &o) { if (p.protocol == "OSPF" && !p.app_text2.empty()) o.addS(p.app_text2); }, "OSPF Area ID"},
                {"ah", FieldType::Boolean, proto<[](const PacketInfo &p) { return p.protocol == "AH" || p.ip_protocol == 51; }>, "IPsec Authentication Header"},
                {"ah.spi", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (p.protocol == "AH" || p.ip_protocol == 51) o.addU(p.tcp_pdu_start); }, "AH Security Parameters Index (SPI)"},
                {"ah.sequence", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (p.protocol == "AH" || p.ip_protocol == 51) o.addU(p.app_code); }, "AH Sequence Number"},
                {"esp", FieldType::Boolean, proto<[](const PacketInfo &p) { return p.protocol == "ESP" || p.ip_protocol == 50; }>, "IPsec Encapsulating Security Payload"},
                {"esp.spi", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (p.protocol == "ESP" || p.ip_protocol == 50) o.addU(p.tcp_pdu_start); }, "ESP Security Parameters Index (SPI)"},
                {"esp.sequence", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (p.protocol == "ESP" || p.ip_protocol == 50) o.addU(p.app_code); }, "ESP Sequence Number"},
                {"ike", FieldType::Boolean, proto<[](const PacketInfo &p) { return p.protocol == "ISAKMP" || p.protocol == "IKEv2"; }>, "Internet Key Exchange / ISAKMP"},
                {"ike.version", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (p.protocol == "ISAKMP" || p.protocol == "IKEv2") o.addU(p.app_code); }, "IKE Version (1 or 2)"},
                {"ike.exchange_type", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (p.protocol == "ISAKMP" || p.protocol == "IKEv2") o.addU(p.app_type); }, "IKE Exchange Type"},
                {"ldap", FieldType::Boolean, proto<[](const PacketInfo &p) { return p.protocol == "LDAP"; }>, "Lightweight Directory Access Protocol"},
                {"ldap.message_id", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (p.protocol == "LDAP") o.addU(p.app_stream); }, "LDAP Message ID"},
                {"ldap.protocol_op", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (p.protocol == "LDAP" && p.app_type != 0xFF) o.addU(p.app_type); }, "LDAP Protocol Operation (Application tag)"},
                {"ldap.name", FieldType::String, [](const PacketInfo &p, const Context &, Values &o) { if (p.protocol == "LDAP" && !p.app_text.empty()) o.addS(p.app_text); }, "LDAP Distinguished Name / Target Object"},
                {"ldap.result_code", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (p.protocol == "LDAP" && (p.app_flags & 1)) o.addU(p.app_code); }, "LDAP result code of a response (0 success, 49 invalidCredentials, ...)"},
                {"ldap.extended_name", FieldType::String, [](const PacketInfo &p, const Context &, Values &o) { if (p.protocol == "LDAP" && !p.app_text2.empty()) o.addS(p.app_text2); }, "LDAP extended operation OID (1.3.6.1.4.1.1466.20037 is StartTLS)"},
                {"kerberos", FieldType::Boolean, proto<[](const PacketInfo &p) { return p.protocol == "Kerberos"; }>, "Kerberos"},
                {"kerberos.msg_type", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (p.protocol == "Kerberos") o.addU(p.app_type); }, "Kerberos message type (10 AS-REQ, 11 AS-REP, 12 TGS-REQ, 13 TGS-REP, 14 AP-REQ, 15 AP-REP, 30 KRB-ERROR)"},
                {"kerberos.error_code", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (p.protocol == "Kerberos" && p.app_type == 30) o.addU(p.app_code); }, "Kerberos KRB-ERROR error code (25 = KDC_ERR_PREAUTH_REQUIRED)"},
                {"kerberos.realm", FieldType::String, [](const PacketInfo &p, const Context &, Values &o) { if (p.protocol == "Kerberos" && !p.app_text.empty()) o.addS(p.app_text); }, "Kerberos realm"},
                {"kerberos.cname", FieldType::String, [](const PacketInfo &p, const Context &, Values &o) { if (p.protocol != "Kerberos") return; const std::string_view v = p.app_text2; const auto c = v.substr(0, v.find('\n')); if (!c.empty()) o.addS(c); }, "Kerberos client principal name"},
                {"kerberos.sname", FieldType::String, [](const PacketInfo &p, const Context &, Values &o) { if (p.protocol != "Kerberos") return; const std::string_view v = p.app_text2; const auto nl = v.find('\n'); if (nl == std::string_view::npos) return; const auto sv = v.substr(nl + 1); if (!sv.empty()) o.addS(sv); }, "Kerberos service principal name"},
                {"pgsql", FieldType::Boolean, proto<[](const PacketInfo &p) { return p.protocol == "PGSQL"; }>, "PostgreSQL frontend/backend protocol"},
                {"pgsql.type", FieldType::String, [](const PacketInfo &p, const Context &, Values &o) { if (p.protocol == "PGSQL" && p.app_type == 6 && p.app_flags > 31 && p.app_flags < 127) { static const std::string_view letters = " !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~"; o.addS(letters.substr(p.app_flags - 32, 1)); } }, "PostgreSQL message type letter (Q SimpleQuery, P Parse, R Authentication, Z ReadyForQuery, ...)"},
                {"pgsql.query", FieldType::String, [](const PacketInfo &p, const Context &, Values &o) { if (p.protocol == "PGSQL" && !p.app_text.empty()) o.addS(p.app_text); }, "PostgreSQL SQL text of a SimpleQuery or Parse message"},
                {"pgsql.user", FieldType::String, [](const PacketInfo &p, const Context &, Values &o) { if (p.protocol == "PGSQL" && p.app_type == 1 && !p.app_text2.empty()) o.addS(p.app_text2); }, "PostgreSQL user of a StartupMessage"},
                {"pgsql.code", FieldType::String, [](const PacketInfo &p, const Context &, Values &o) { if (p.protocol == "PGSQL" && p.app_type == 6 && (p.app_flags == 'E' || p.app_flags == 'N') && !p.app_text2.empty()) o.addS(p.app_text2); }, "PostgreSQL SQLSTATE of an ErrorResponse / NoticeResponse"},
                {"pgsql.ssl_request", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (p.protocol == "PGSQL") o.addU(p.app_type == 2); }, "PostgreSQL SSLRequest"},
                {"mysql", FieldType::Boolean, proto<[](const PacketInfo &p) { return p.protocol == "MySQL"; }>, "MySQL client/server protocol"},
                {"mysql.command", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (p.protocol == "MySQL" && (p.app_flags & 32)) o.addU(p.app_type); }, "MySQL command of a client packet (3 COM_QUERY, 2 COM_INIT_DB, 1 COM_QUIT, 22 COM_STMT_PREPARE, ...)"},
                {"mysql.query", FieldType::String, [](const PacketInfo &p, const Context &, Values &o) { if (p.protocol == "MySQL" && !p.app_text.empty()) o.addS(p.app_text); }, "MySQL SQL text of COM_QUERY / COM_STMT_PREPARE (or the schema of COM_INIT_DB)"},
                {"mysql.error_code", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (p.protocol == "MySQL" && (p.app_flags & 2)) o.addU(p.app_code); }, "MySQL error code of an ERR packet"},
                {"mysql.version", FieldType::String, [](const PacketInfo &p, const Context &, Values &o) { if (p.protocol == "MySQL" && (p.app_flags & 4) && !p.app_text2.empty()) o.addS(p.app_text2); }, "MySQL server version of the initial handshake"},
                {"mysql.user", FieldType::String, [](const PacketInfo &p, const Context &, Values &o) { if (p.protocol == "MySQL" && (p.app_flags & 8) && !p.app_text2.empty()) o.addS(p.app_text2); }, "MySQL user name of the login request"},
                {"mysql.packet_number", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (p.protocol == "MySQL") o.addU(p.app_stream); }, "MySQL packet (sequence) number"},
                {"mysql.from_server", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (p.protocol == "MySQL") o.addU((p.app_flags & 1) != 0); }, "MySQL packet sent by the server"},
                {"mysql.ssl_request", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (p.protocol == "MySQL") o.addU((p.app_flags & 16) != 0); }, "MySQL SSL request (TLS handshake follows)"},
                {"tds", FieldType::Boolean, proto<[](const PacketInfo &p) { return p.protocol == "TDS"; }>, "Tabular Data Stream (SQL Server)"},
                {"tds.type", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (p.protocol == "TDS") o.addU(p.app_type); }, "TDS packet type (1 SQL Batch, 3 RPC, 4 Tabular Response, 16 Login7, 18 Pre-Login)"},
                {"tds.status", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (p.protocol == "TDS") o.addU(p.app_flags & 0xff); }, "TDS status byte (bit 0 = end of message)"},
                {"tds.spid", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (p.protocol == "TDS") o.addU(p.app_code); }, "TDS server process id of the packet header"},
                {"tds.query", FieldType::String, [](const PacketInfo &p, const Context &, Values &o) { if (p.protocol == "TDS" && !p.app_text.empty()) o.addS(p.app_text); }, "TDS SQL Batch text or RPC procedure name"},
                {"tds.user", FieldType::String, [](const PacketInfo &p, const Context &, Values &o) { if (p.protocol == "TDS" && (p.app_flags & 0x400) && !p.app_text2.empty()) o.addS(p.app_text2); }, "TDS Login7 user name"},
                {"tds.encryption", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (p.protocol == "TDS" && (p.app_flags & 0x200)) o.addU((p.app_flags >> 12) & 3); }, "TDS Pre-Login ENCRYPTION option (0 OFF, 1 ON, 2 NOT_SUP, 3 REQ)"},
                {"tds.error_number", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (p.protocol == "TDS" && (p.app_flags & 0x100)) o.addU(p.app_stream); }, "TDS ERROR token number (18456 = login failed)"},
                {"smb2", FieldType::Boolean, proto<[](const PacketInfo &p) { return p.protocol == "SMB2"; }>, "SMB2 / SMB3"},
                {"smb2.cmd", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (p.protocol == "SMB2" && !(p.app_flags & 0xC)) o.addU(p.app_type); }, "SMB2 command of the first message in the packet (0 Negotiate, 1 Session Setup, 3 Tree Connect, 5 Create, 8 Read, 9 Write)"},
                {"smb2.flags.response", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (p.protocol == "SMB2" && !(p.app_flags & 0xC)) o.addU((p.app_flags & 1) != 0); }, "SMB2 response flag of the first message"},
                {"smb2.flags.signed", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (p.protocol == "SMB2" && !(p.app_flags & 0xC)) o.addU((p.app_flags & 2) != 0); }, "SMB2 signed flag of the first message"},
                {"smb2.encrypted", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (p.protocol == "SMB2") o.addU((p.app_flags & 4) != 0); }, "SMB3 message in a Transform header (encrypted, content not shown)"},
                {"smb2.nt_status", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (p.protocol == "SMB2" && (p.app_flags & 1) && !(p.app_flags & 0xC)) o.addU(p.app_stream); }, "SMB2 NT status of a response (first message)"},
                {"smb2.dialect", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (p.protocol == "SMB2" && (p.app_flags & 0x10)) o.addU(p.app_code); }, "SMB2 dialect revision chosen by a Negotiate response (0x0311 = SMB 3.1.1)"},
                {"smb2.tree", FieldType::String, [](const PacketInfo &p, const Context &, Values &o) { if (p.protocol == "SMB2" && p.app_type == 3 && !(p.app_flags & 0xD) && !p.app_text.empty()) o.addS(p.app_text); }, "SMB2 share path of a Tree Connect request"},
                {"smb2.filename", FieldType::String, [](const PacketInfo &p, const Context &, Values &o) { if (p.protocol == "SMB2" && p.app_type == 5 && !(p.app_flags & 0xD) && !p.app_text.empty()) o.addS(p.app_text); }, "SMB2 file name of a Create request"},
                {"smb2.user", FieldType::String, [](const PacketInfo &p, const Context &, Values &o) { if (p.protocol == "SMB2" && p.app_type == 1 && !(p.app_flags & 0xD) && !p.app_text.empty()) o.addS(p.app_text); }, "SMB2 user of an NTLMSSP authenticate message (domain\\user)"},
                {"dcerpc", FieldType::Boolean, proto<[](const PacketInfo &p) { return p.protocol == "DCERPC"; }>, "DCE/RPC"},
                {"dcerpc.pkt_type", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (p.protocol == "DCERPC") o.addU(p.app_type); }, "DCE/RPC PDU type (0 Request, 2 Response, 3 Fault, 11 Bind, 12 Bind_ack)"},
                {"dcerpc.opnum", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (p.protocol == "DCERPC" && (p.app_flags & 1)) o.addU(p.app_code); }, "DCE/RPC operation number of a Request"},
                {"dcerpc.cn_call_id", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (p.protocol == "DCERPC") o.addU(p.app_stream); }, "DCE/RPC call id"},
                {"dcerpc.if_uuid", FieldType::String, [](const PacketInfo &p, const Context &, Values &o) { if (p.protocol == "DCERPC" && !p.app_text.empty()) o.addS(p.app_text); }, "DCE/RPC interface UUID of the first presentation context of a Bind / Alter_context"},
                {"rpc", FieldType::Boolean, proto<isRpc>, "ONC RPC (also NFS, Portmap and Mount)"},
                {"rpc.xid", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isRpc(p)) o.addU(p.app_stream); }, "ONC RPC transaction id"},
                {"rpc.msgtyp", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isRpc(p)) o.addU(p.app_flags & 1); }, "ONC RPC message type (0 call, 1 reply)"},
                {"rpc.program", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isRpcCall(p)) o.addU(std::strtoull(p.app_text.c_str(), nullptr, 10)); }, "ONC RPC program number of a call (100003 NFS, 100000 Portmap, 100005 Mount)"},
                {"rpc.programversion", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isRpcCall(p)) o.addU(p.app_code); }, "ONC RPC program version of a call"},
                {"rpc.procedure", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isRpcCall(p)) o.addU(p.app_type); }, "ONC RPC procedure number of a call"},
                {"rpc.state_accept", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (p.protocol == "RPC" && (p.app_flags & 1) && !(p.app_flags & 2)) o.addU(p.app_code); }, "ONC RPC accept status of an accepted reply (0 SUCCESS, 1 PROG_UNAVAIL, 2 PROG_MISMATCH, 3 PROC_UNAVAIL ...)"},
                {"rpc.reply_denied", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (p.protocol == "RPC" && (p.app_flags & 1)) o.addU((p.app_flags & 2) != 0); }, "ONC RPC reply that was denied (RPC_MISMATCH or AUTH_ERROR)"},
                {"nfs", FieldType::Boolean, proto<[](const PacketInfo &p) { return p.protocol == "NFS" || p.protocol == "NFSv4"; }>, "Network File System call"},
                {"nfs.proc", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (p.protocol == "NFS" || p.protocol == "NFSv4") o.addU(p.app_type); }, "NFS procedure of a call (v3: 1 GETATTR, 3 LOOKUP, 6 READ, 7 WRITE; v4: 1 COMPOUND)"},
                {"nfs.version", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (p.protocol == "NFS" || p.protocol == "NFSv4") o.addU(p.app_code); }, "NFS protocol version of a call"},
                {"nfs.name", FieldType::String, [](const PacketInfo &p, const Context &, Values &o) { if ((p.protocol == "NFS" || p.protocol == "NFSv4") && !p.app_text2.empty()) o.addS(p.app_text2); }, "NFS file name of a LOOKUP / CREATE / MKDIR / REMOVE / RMDIR call"},
                {"portmap.proc", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (p.protocol == "Portmap") o.addU(p.app_type); }, "Portmap procedure of a call (3 GETPORT)"},
                {"mount.path", FieldType::String, [](const PacketInfo &p, const Context &, Values &o) { if (p.protocol == "Mount" && !p.app_text2.empty()) o.addS(p.app_text2); }, "Mount directory path of a MNT / UMNT call"},
                // ---- application protocols (by the protocol column)
                {"dhcp.type", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "DHCP") && p.app_type != 0) o.addU(p.app_type); }, "DHCP message type (1 = Discover, 2 = Offer, 3 = Request, 5 = ACK ...)"},
                {"dhcp.option.hostname", FieldType::String, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "DHCP") && !p.app_text.empty()) o.addS(p.app_text); }, "DHCP host name option"},
                {"ntp", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "NTP")) o.addU(1); }, "NTP"},
                {"ntp.mode", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "NTP")) o.addU(p.app_type); }, "NTP mode (3 = client, 4 = server)"},
                {"ntp.stratum", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "NTP") && p.app_type >= 1 && p.app_type <= 5) o.addU(p.app_code); }, "NTP stratum"},
                {"ntp.ctrl.opcode", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "NTP") && p.app_type == 6) o.addU(p.app_code); }, "Opcode of an NTP control message (2 = read variables)"},
                {"ntp.priv.reqcode", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "NTP") && p.app_type == 7) o.addU(p.app_code); }, "Request code of an NTP private (mode 7) message"},
                {"ntp.version", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "NTP")) o.addU(p.app_flags); }, "NTP version"},
                {"dns.qry.name", FieldType::String, [](const PacketInfo &p, const Context &, Values &o) { if ((isProtocol(p, "DNS") || isProtocol(p, "MDNS")) && !p.app_text.empty()) o.addS(p.app_text); }, "Name of the first DNS question"},
                {"dns.qry.type", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if ((isProtocol(p, "DNS") || isProtocol(p, "MDNS")) && !p.app_text.empty()) o.addU(p.app_type); }, "Type of the first DNS question (1 = A, 28 = AAAA, 15 = MX ...)"},
                {"dns.flags.response", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "DNS") || isProtocol(p, "MDNS")) o.addU((p.app_flags & 0x8000) != 0); }, "DNS message is a response"},
                {"dns.flags.rcode", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "DNS") || isProtocol(p, "MDNS")) o.addU(p.app_code); }, "DNS reply code (0 = no error, 3 = NXDOMAIN ...)"},
                {"dns.flags.truncated", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "DNS") || isProtocol(p, "MDNS")) o.addU((p.app_flags & 0x0200) != 0); }, "DNS message is truncated"},
                {"mdns", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "MDNS")) o.addU(1); }, "Multicast DNS"},
                {"dns", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "DNS")) o.addU(1); }, "DNS"},
                {"dhcp", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "DHCP")) o.addU(1); }, "DHCP"},
                {"snmp", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "SNMP")) o.addU(1); }, "SNMP"},
                {"snmp.version", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "SNMP")) o.addU(p.app_flags); }, "SNMP version (0 = v1, 1 = v2c, 3 = v3)"},
                {"snmp.community", FieldType::String, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "SNMP") && !p.app_text.empty()) o.addS(p.app_text); }, "SNMP community string or v3 user name"},
                {"snmp.pdu_type", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "SNMP")) o.addU(p.app_type); }, "SNMP PDU type (0 = GetRequest, 1 = GetNextRequest, 2 = Response ...)"},
                {"snmp.request_id", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "SNMP")) o.addU(p.tcp_pdu_start); }, "SNMP request ID"},
                {"snmp.error_status", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "SNMP")) o.addU(p.app_code); }, "SNMP error-status code"},
                {"snmp.oid", FieldType::String, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "SNMP") && !p.app_text2.empty()) o.addS(p.app_text2); }, "SNMP first variable binding OID"},
                {"telnet", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "Telnet")) o.addU(1); }, "Telnet"},
                {"telnet.cmd", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "Telnet") && p.app_type != 0) o.addU(p.app_type); }, "Telnet command (251 = WILL, 252 = WONT, 253 = DO, 254 = DONT, 250 = SB...)"},
                {"telnet.subcmd", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "Telnet") && p.app_code != 0) o.addU(p.app_code); }, "Telnet option code (1 = Echo, 3 = Suppress Go Ahead, 24 = Terminal Type, 31 = NAWS...)"},
                {"telnet.data", FieldType::String, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "Telnet") && !p.app_text.empty()) o.addS(p.app_text); }, "Telnet text data or command summary"},
                {"smtp", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "SMTP")) o.addU(1); }, "SMTP"},
                {"smtp.req", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "SMTP") && p.app_type == 1) o.addU(1); }, "SMTP command/request"},
                {"smtp.rsp", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "SMTP") && p.app_type == 2) o.addU(1); }, "SMTP server response"},
                {"smtp.response.code", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "SMTP") && p.app_type == 2 && p.app_code != 0) o.addU(p.app_code); }, "SMTP response code (e.g. 220, 250, 354, 550)"},
                {"smtp.command", FieldType::String, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "SMTP") && p.app_type == 1 && !p.app_text.empty()) o.addS(p.app_text); }, "SMTP command name (e.g. EHLO, MAIL FROM, RCPT TO, DATA)"},
                {"smtp.param", FieldType::String, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "SMTP") && !p.app_text2.empty()) o.addS(p.app_text2); }, "SMTP command or response parameter"},
                {"ftp", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "FTP")) o.addU(1); }, "FTP"},
                {"ftp.req", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "FTP") && p.app_type == 1) o.addU(1); }, "FTP command/request"},
                {"ftp.rsp", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "FTP") && p.app_type == 2) o.addU(1); }, "FTP server response"},
                {"ftp.response.code", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "FTP") && p.app_type == 2 && p.app_code != 0) o.addU(p.app_code); }, "FTP response code (e.g. 200, 220, 227, 230, 550)"},
                {"ftp.command", FieldType::String, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "FTP") && p.app_type == 1 && !p.app_text.empty()) o.addS(p.app_text); }, "FTP command name (e.g. USER, PASS, PORT, PASV, RETR)"},
                {"ftp.arg", FieldType::String, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "FTP") && !p.app_text2.empty()) o.addS(p.app_text2); }, "FTP command or response argument"},
                {"ftp_data", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "FTP-DATA")) o.addU(1); }, "FTP-DATA"},
                {"tftp", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "TFTP")) o.addU(1); }, "TFTP"},
                {"tftp.opcode", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "TFTP") && p.app_type != 0) o.addU(p.app_type); }, "TFTP opcode (1 = RRQ, 2 = WRQ, 3 = DATA, 4 = ACK, 5 = ERROR, 6 = OACK)"},
                {"tftp.block", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "TFTP") && (p.app_type == 3 || p.app_type == 4)) o.addU(p.app_code); }, "TFTP block number"},
                {"tftp.error.code", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "TFTP") && p.app_type == 5) o.addU(p.app_code); }, "TFTP error code"},
                {"tftp.source_file", FieldType::String, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "TFTP") && (p.app_type == 1 || p.app_type == 2) && !p.app_text.empty()) o.addS(p.app_text); }, "TFTP filename"},
                {"tftp.mode", FieldType::String, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "TFTP") && (p.app_type == 1 || p.app_type == 2) && !p.app_text2.empty()) o.addS(p.app_text2); }, "TFTP transfer mode (e.g. netascii, octet)"},
                {"bgp", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "BGP")) o.addU(1); }, "BGP"},
                {"bgp.type", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "BGP")) o.addU(p.app_type); }, "BGP message type (1 = OPEN, 2 = UPDATE, 3 = NOTIFICATION, 4 = KEEPALIVE, 5 = ROUTE-REFRESH)"},
                {"bgp.as", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "BGP")) o.addU(p.tcp_pdu_start); }, "BGP Autonomous System number"},
                {"bgp.nlri", FieldType::String, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "BGP") && !p.app_text.empty()) o.addS(p.app_text); }, "BGP Network Layer Reachability Information prefix"},
                {"bgp.notification.code", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "BGP") && p.app_type == 3) o.addU(p.app_code); }, "BGP notification error code"},
                {"ssh", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "SSH")) o.addU(1); }, "SSH"},
                {"ssh.protocol", FieldType::String, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "SSH") && p.app_type == 0 && !p.app_text.empty()) o.addS(p.app_text); }, "SSH protocol version banner"},
                {"ssh.message_code", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "SSH") && p.app_type != 0 && p.app_type != 255) o.addU(p.app_type); }, "SSH packet message code (e.g. 20 = KEXINIT, 21 = NEWKEYS)"},
                {"ssh.kex_algorithm", FieldType::String, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "SSH") && p.app_type == 20 && !p.app_text.empty()) o.addS(p.app_text); }, "SSH key exchange algorithm"},
                {"ssh.encryption_algorithm", FieldType::String, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "SSH") && p.app_type == 20 && !p.app_text2.empty()) o.addS(p.app_text2); }, "SSH client-to-server encryption algorithm"},
                {"ssh.encrypted", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "SSH") && p.app_type == 255) o.addU(1); }, "SSH encrypted packet payload"},
                {"wlan", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (p.link_type == 105 || p.link_type == 127 || p.link_type == 192 || isProtocol(p, "802.11") || isProtocol(p, "WLAN") || p.wlan_fc != 0) o.addU(1); }, "IEEE 802.11 wireless frame"},
                {"wlan.fc.type", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (p.wlan_fc != 0 || isProtocol(p, "802.11") || isProtocol(p, "WLAN")) o.addU((p.wlan_fc >> 2) & 0x03); }, "802.11 Frame Control type (0 = Management, 1 = Control, 2 = Data, 3 = Extension)"},
                {"wlan.fc.subtype", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (p.wlan_fc != 0 || isProtocol(p, "802.11") || isProtocol(p, "WLAN")) o.addU((p.wlan_fc >> 4) & 0x0F); }, "802.11 Frame Control subtype"},
                {"wlan.fc.protected", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (p.wlan_fc != 0 || isProtocol(p, "802.11") || isProtocol(p, "WLAN")) o.addU((p.wlan_fc & 0x4000) ? 1 : 0); }, "802.11 Frame Control protected (encrypted) bit"},
                {"wlan.fc.retry", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (p.wlan_fc != 0 || isProtocol(p, "802.11") || isProtocol(p, "WLAN")) o.addU((p.wlan_fc & 0x0800) ? 1 : 0); }, "802.11 Frame Control retry bit"},
                {"wlan.fc.tods", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (p.wlan_fc != 0 || isProtocol(p, "802.11") || isProtocol(p, "WLAN")) o.addU((p.wlan_fc & 0x0100) ? 1 : 0); }, "802.11 Frame Control To DS bit"},
                {"wlan.fc.fromds", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (p.wlan_fc != 0 || isProtocol(p, "802.11") || isProtocol(p, "WLAN")) o.addU((p.wlan_fc & 0x0200) ? 1 : 0); }, "802.11 Frame Control From DS bit"},
                {"wlan.seq", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (p.wlan_fc != 0 || isProtocol(p, "802.11") || isProtocol(p, "WLAN")) o.addU(p.wlan_seq); }, "802.11 sequence number"},
                {"wlan.sa", FieldType::String, [](const PacketInfo &p, const Context &, Values &o) { if ((isProtocol(p, "802.11") || isProtocol(p, "WLAN")) && !p.source.empty()) o.addS(p.source); }, "802.11 Source MAC address"},
                {"wlan.da", FieldType::String, [](const PacketInfo &p, const Context &, Values &o) { if ((isProtocol(p, "802.11") || isProtocol(p, "WLAN")) && !p.destination.empty()) o.addS(p.destination); }, "802.11 Destination MAC address"},
                {"wlan.ra", FieldType::String, [](const PacketInfo &p, const Context &, Values &o) { if ((isProtocol(p, "802.11") || isProtocol(p, "WLAN")) && !p.destination.empty()) o.addS(p.destination); }, "802.11 Receiver MAC address"},
                {"wlan.ta", FieldType::String, [](const PacketInfo &p, const Context &, Values &o) { if ((isProtocol(p, "802.11") || isProtocol(p, "WLAN")) && !p.source.empty()) o.addS(p.source); }, "802.11 Transmitter MAC address"},
                {"wlan.bssid", FieldType::String, [](const PacketInfo &p, const Context &, Values &o) { if ((isProtocol(p, "802.11") || isProtocol(p, "WLAN")) && !p.app_text2.empty()) o.addS(p.app_text2); }, "802.11 BSSID MAC address"},
                {"wlan.ssid", FieldType::String, [](const PacketInfo &p, const Context &, Values &o) { if ((isProtocol(p, "802.11") || isProtocol(p, "WLAN")) && !p.app_text.empty()) o.addS(p.app_text); }, "802.11 SSID"},
                {"radiotap.channel.freq", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (p.radiotap_freq != 0) o.addU(p.radiotap_freq); }, "Radiotap/PPI channel frequency in MHz"},
                {"radiotap.dbm_antsignal", FieldType::Float, [](const PacketInfo &p, const Context &, Values &o) { if (p.radiotap_signal != 0) o.addD(static_cast<double>(p.radiotap_signal)); }, "Radiotap/PPI antenna signal in dBm"},
                {"radiotap.datarate", FieldType::Float, [](const PacketInfo &p, const Context &, Values &o) { if (p.radiotap_rate != 0) o.addD(p.radiotap_rate * 0.5); }, "Radiotap/PPI data rate in Mb/s"},
                {"ppi.dlt", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (p.ppi_dlt != 0) o.addU(p.ppi_dlt); }, "PPI encapsulated Data Link Type"},
                {"eapol", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "EAPOL") || isProtocol(p, "EAP") || p.ether_type == 0x888E) o.addU(1); }, "IEEE 802.1X / EAPOL packet"},
                {"eapol.type", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "EAPOL") || isProtocol(p, "EAP") || p.ether_type == 0x888E) o.addU(p.app_type); }, "802.1X packet type (0 = EAP, 1 = Start, 2 = Logoff, 3 = Key)"},
                {"eapol.keydes.type", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "EAPOL") && p.app_type == 3) o.addU(p.app_code); }, "EAPOL-Key descriptor type (1 = RC4, 2 = RSN, 254 = WPA)"},
                {"eapol.keydes.msgnr", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "EAPOL") && p.app_type == 3 && p.app_flags != 0) o.addU(p.app_flags); }, "WPA 4-way handshake message number (1, 2, 3, 4)"},
                {"eap", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "EAP") || (isProtocol(p, "EAPOL") && p.app_type == 0)) o.addU(1); }, "Extensible Authentication Protocol"},
                {"eap.code", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "EAP") && p.app_code != 0) o.addU(p.app_code); }, "EAP code (1 = Request, 2 = Response, 3 = Success, 4 = Failure)"},
                {"eap.type", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "EAP") && p.app_flags != 0) o.addU(p.app_flags); }, "EAP type (1 = Identity, 13 = TLS, 25 = PEAP, 43 = FAST)"},
                {"eap.identity", FieldType::String, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "EAP") && p.app_flags == 1 && !p.app_text.empty()) o.addS(p.app_text); }, "EAP Identity username/string"},
                {"llc", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (isLlc(p)) o.addU(1); }, "IEEE 802.2 Logical-Link Control"},
                {"llc.dsap", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "LLC") || isProtocol(p, "SNAP")) o.addU(p.app_type); else if (isStp(p)) o.addU(0x42); }, "LLC Destination Service Access Point (DSAP)"},
                {"llc.ssap", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "LLC") || isProtocol(p, "SNAP")) o.addU(p.app_flags & 0xFF); else if (isStp(p)) o.addU(0x42); }, "LLC Source Service Access Point (SSAP)"},
                {"llc.control", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "LLC") || isProtocol(p, "SNAP")) o.addU(p.app_code); else if (isStp(p)) o.addU(0x03); }, "LLC Control Field"},
                {"snap", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (isSnap(p)) o.addU(1); }, "Subnetwork Access Protocol (SNAP)"},
                {"snap.oui", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isSnap(p)) o.addU(p.tcp_pdu_start); }, "SNAP Organizationally Unique Identifier (OUI)"},
                {"snap.type", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isSnap(p) && p.ether_type != 0) o.addU(p.ether_type); }, "SNAP Protocol ID / EtherType"},
                {"stp", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (isStp(p)) o.addU(1); }, "Spanning Tree Protocol (STP / RSTP / MSTP)"},
                {"stp.protocol", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isStp(p)) o.addU(0); }, "STP Protocol Identifier"},
                {"stp.version", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isStp(p)) o.addU(p.app_flags & 0xFF); }, "STP Protocol Version Identifier (0 = STP, 2 = RSTP, 3 = MSTP)"},
                {"stp.bpdu.type", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isStp(p)) o.addU(p.app_type); }, "STP BPDU Type (0x00 = Config, 0x02 = RST, 0x80 = TCN)"},
                {"stp.flags", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isStp(p) && (p.app_type == 0 || p.app_type == 2)) o.addU((p.app_flags >> 8) & 0xFF); }, "STP BPDU Flags byte"},
                {"stp.flags.tc", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (isStp(p) && (p.app_type == 0 || p.app_type == 2)) o.addU(((p.app_flags >> 8) & 0x01) ? 1 : 0); }, "STP Topology Change flag"},
                {"stp.flags.proposal", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (isStp(p) && (p.app_type == 0 || p.app_type == 2)) o.addU(((p.app_flags >> 8) & 0x02) ? 1 : 0); }, "STP Proposal flag"},
                {"stp.flags.port_role", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isStp(p) && (p.app_type == 0 || p.app_type == 2)) o.addU(((p.app_flags >> 8) >> 2) & 0x03); }, "STP Port Role (1 = Alternate/Backup, 2 = Root, 3 = Designated)"},
                {"stp.flags.learning", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (isStp(p) && (p.app_type == 0 || p.app_type == 2)) o.addU(((p.app_flags >> 8) & 0x10) ? 1 : 0); }, "STP Learning flag"},
                {"stp.flags.forwarding", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (isStp(p) && (p.app_type == 0 || p.app_type == 2)) o.addU(((p.app_flags >> 8) & 0x20) ? 1 : 0); }, "STP Forwarding flag"},
                {"stp.flags.agreement", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (isStp(p) && (p.app_type == 0 || p.app_type == 2)) o.addU(((p.app_flags >> 8) & 0x40) ? 1 : 0); }, "STP Agreement flag"},
                {"stp.flags.tc_ack", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (isStp(p) && (p.app_type == 0 || p.app_type == 2)) o.addU(((p.app_flags >> 8) & 0x80) ? 1 : 0); }, "STP Topology Change Acknowledgment flag"},
                {"stp.root.cost", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isStp(p) && (p.app_type == 0 || p.app_type == 2)) o.addU(p.tcp_pdu_start); }, "STP Root Path Cost"},
                {"stp.root.id", FieldType::String, [](const PacketInfo &p, const Context &, Values &o) { if (isStp(p) && !p.app_text.empty()) o.addS(p.app_text); }, "STP Root Identifier"},
                {"stp.bridge.id", FieldType::String, [](const PacketInfo &p, const Context &, Values &o) { if (isStp(p) && !p.app_text2.empty()) o.addS(p.app_text2); }, "STP Bridge Identifier"},
                {"stp.port", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isStp(p) && (p.app_type == 0 || p.app_type == 2)) o.addU(p.app_code); }, "STP Port Identifier"},
                {"ppp", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (isPpp(p)) o.addU(1); }, "Point-to-Point Protocol"},
                {"ppp.protocol", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (!isMpls(p) && p.ppp_protocol != 0) o.addU(p.ppp_protocol); }, "PPP Protocol ID (0x0021 = IPv4, 0x0057 = IPv6, 0xc021 = LCP, 0x8021 = IPCP)"},
                {"ppp.lcp.code", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (!isMpls(p) && (p.ppp_protocol == 0xc021 || isProtocol(p, "LCP"))) o.addU(p.app_type); }, "LCP Code (1 = Config-Req, 2 = Config-Ack, etc.)"},
                {"ppp.ipcp.code", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (!isMpls(p) && (p.ppp_protocol == 0x8021 || isProtocol(p, "IPCP"))) o.addU(p.app_type); }, "IPCP Code"},
                {"pppoe", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (isPppoe(p)) o.addU(1); }, "PPP-over-Ethernet (Discovery or Session)"},
                {"pppoed", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (p.ether_type == 0x8863 || isProtocol(p, "PPPoED")) o.addU(1); }, "PPPoE Discovery Stage"},
                {"pppoes", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (p.ether_type == 0x8864 || isProtocol(p, "PPPoES") || (p.link_type == 1 && isPpp(p))) o.addU(1); }, "PPPoE Session Stage"},
                {"pppoe.code", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isPppoe(p)) o.addU(p.pppoe_code); }, "PPPoE Code (0x00 = Session, 0x09 = PADI, 0x07 = PADO, 0x19 = PADR, 0x65 = PADS, 0xa7 = PADT)"},
                {"pppoe.session_id", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isPppoe(p)) o.addU(p.pppoe_session_id); }, "PPPoE Session ID"},
                {"pppoe.service_name", FieldType::String, [](const PacketInfo &p, const Context &, Values &o) { if (isPppoe(p) && !p.app_text.empty()) o.addS(p.app_text); }, "PPPoE Service-Name tag"},
                {"pppoe.ac_name", FieldType::String, [](const PacketInfo &p, const Context &, Values &o) { if (isPppoe(p) && !p.app_text2.empty()) o.addS(p.app_text2); }, "PPPoE Access Concentrator (AC) Name tag"},
                {"mpls", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (isMpls(p)) o.addU(1); }, "MultiProtocol Label Switching"},
                {"mpls.label", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isMpls(p)) o.addU((p.mplsLse(0) >> 12) & 0xFFFFF); }, "MPLS Label Value (outermost label)"},
                {"mpls.exp", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isMpls(p)) o.addU((p.mplsLse(0) >> 9) & 0x07); }, "MPLS Experimental (TC) Bits"},
                {"mpls.ttl", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isMpls(p)) o.addU(p.mplsLse(0) & 0xFF); }, "MPLS Time To Live"},
                {"mpls.bottom_of_stack", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (isMpls(p)) o.addU((p.mplsLse(0) >> 8) & 0x01); }, "MPLS Bottom of Stack flag (outermost label)"},
                {"mpls.label1", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isMpls(p) && !((p.mplsLse(0) >> 8) & 0x01)) o.addU((p.mplsLse(1) >> 12) & 0xFFFFF); }, "MPLS Label Value (second label in the stack)"},
                {"ipip", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (isIpip(p)) o.addU(1); }, "IP-in-IP tunnel (protocol 4 or 41)"},
                {"gre", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (isGre(p)) o.addU(1); }, "Generic Routing Encapsulation"},
                {"gre.proto", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isGre(p)) o.addU(p.gre_proto); }, "GRE Protocol Type (0x0800 = IPv4, 0x86DD = IPv6, 0x6558 = Ethernet, 0x880B = PPP)"},
                {"gre.version", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isGre(p)) o.addU(p.gre_flags & 0x0007); }, "GRE Version (0 = RFC 2784, 1 = Enhanced GRE/RFC 2637)"},
                {"gre.flags.checksum", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (isGre(p)) o.addU((p.gre_flags & 0x8000) ? 1 : 0); }, "GRE Checksum present flag"},
                {"gre.flags.routing", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (isGre(p)) o.addU((p.gre_flags & 0x4000) ? 1 : 0); }, "GRE Routing present flag"},
                {"gre.flags.key", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (isGre(p)) o.addU((p.gre_flags & 0x2000) ? 1 : 0); }, "GRE Key present flag"},
                {"gre.flags.sequence", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (isGre(p)) o.addU((p.gre_flags & 0x1000) ? 1 : 0); }, "GRE Sequence Number present flag"},
                {"gre.key", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isGre(p) && (p.gre_flags & 0x2000)) o.addU(p.gre_key); }, "GRE Key (low 16 bits)"},
                {"gre.sequence_number", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isGre(p) && (p.gre_flags & 0x1000)) o.addU(p.gre_seq); }, "GRE Sequence Number (low 16 bits)"},
                {"lldp", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (isLldp(p)) o.addU(1); }, "Link Layer Discovery Protocol"},
                {"lldp.chassis_id", FieldType::String, [](const PacketInfo &p, const Context &, Values &o) { if (isLldp(p) && !p.app_text.empty()) o.addS(p.app_text); }, "LLDP Chassis ID"},
                {"lldp.port_id", FieldType::String, [](const PacketInfo &p, const Context &, Values &o) { if (isLldp(p) && !p.app_text2.empty()) o.addS(p.app_text2); }, "LLDP Port ID"},
                {"lldp.ttl", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isLldp(p)) o.addU(p.app_code); }, "LLDP Time To Live in seconds"},
                {"lldp.capabilities", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isLldp(p)) o.addU(p.app_flags); }, "LLDP System Capabilities (enabled bits)"},
                {"lacp", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (isLacp(p)) o.addU(1); }, "Link Aggregation Control Protocol"},
                {"lacp.actor.system", FieldType::String, [](const PacketInfo &p, const Context &, Values &o) { if (isLacp(p) && !p.app_text.empty()) o.addS(p.app_text); }, "LACP Actor System ID (MAC)"},
                {"lacp.partner.system", FieldType::String, [](const PacketInfo &p, const Context &, Values &o) { if (isLacp(p) && !p.app_text2.empty()) o.addS(p.app_text2); }, "LACP Partner System ID (MAC)"},
                {"lacp.actor.port", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isLacp(p)) o.addU(p.app_type); }, "LACP Actor Port number"},
                {"lacp.partner.port", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isLacp(p)) o.addU(p.app_code); }, "LACP Partner Port number"},
                {"lacp.actor.state", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isLacp(p)) o.addU(p.app_flags & 0xFF); }, "LACP Actor State byte"},
                {"lacp.partner.state", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isLacp(p)) o.addU((p.app_flags >> 8) & 0xFF); }, "LACP Partner State byte"},
                {"lacp.actor.state.activity", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (isLacp(p)) o.addU((p.app_flags & 0x01) ? 1 : 0); }, "LACP Actor Activity bit"},
                {"lacp.actor.state.synchronization", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (isLacp(p)) o.addU((p.app_flags & 0x08) ? 1 : 0); }, "LACP Actor Synchronization bit"},
                {"lacp.actor.state.collecting", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (isLacp(p)) o.addU((p.app_flags & 0x10) ? 1 : 0); }, "LACP Actor Collecting bit"},
                {"lacp.actor.state.distributing", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (isLacp(p)) o.addU((p.app_flags & 0x20) ? 1 : 0); }, "LACP Actor Distributing bit"},
                {"mac_control", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (isMacControl(p)) o.addU(1); }, "Ethernet MAC Control"},
                {"mac_control.opcode", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isMacControl(p)) o.addU(p.app_code); }, "MAC Control opcode (0x0001 PAUSE, 0x0101 PFC)"},
                {"pause", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (isMacControl(p) && p.app_code == 0x0001) o.addU(1); }, "Ethernet PAUSE frame"},
                {"pause.time", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isMacControl(p) && p.app_code == 0x0001) o.addU(p.app_type); }, "PAUSE time (units of 512 bit times)"},
                {"pfc", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (isMacControl(p) && p.app_code == 0x0101) o.addU(1); }, "Priority Flow Control frame"},
                {"pfc.class_enable", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isMacControl(p) && p.app_code == 0x0101) o.addU(p.app_type); }, "PFC Class Enable Vector"},
                {"bt.handle", FieldType::String, [](const PacketInfo &p, const Context &, Values &o) { if (!isBluetooth(p)) return; for (const std::string *a: {&p.source, &p.destination}) if (a->rfind("0x", 0) == 0) o.addS(*a); }, "Bluetooth ACL connection handle (0x0040 form)"},
                {"bt.addr", FieldType::String, [](const PacketInfo &p, const Context &, Values &o) { if (!isBluetooth(p)) return; if (!p.source.empty()) o.addS(p.source); if (!p.destination.empty()) o.addS(p.destination); }, "Bluetooth source or destination: host, controller (hciN), or a connection handle"},
                {"usb", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (isUsb(p)) o.addU(1); }, "USB packet"},
                {"usb.device", FieldType::String, [](const PacketInfo &p, const Context &, Values &o) { if (!isUsb(p)) return; for (const std::string *a: {&p.source, &p.destination}) if (!a->empty() && *a != "host") o.addS(*a); }, "USB device address (bus.device)"},
            };
            return t;
        }

        // The built-in table: every field module, registered once. Built on first use (before any filter is compiled and
        // before any packet is dissected) and never changed afterwards, so findField() pointers into it stay valid for the
        // life of the process. registerField() is for fields added later (plugins, tests): it keeps them in a deque,
        // whose elements never move, behind a mutex, and never touches the built table.
        const std::vector<FieldDef> &baseTable() {
            static const std::vector<FieldDef> table = [] {
                FieldRegistry registry;
                registerBuiltinFields(registry);
                registry.addAll(legacyRows());
                if (!registry.problems().empty()) {
                    for (const auto &problem: registry.problems()) std::fprintf(stderr, "imshark: filter field table: %s\n", problem.c_str());
                    std::abort();
                }
                return registry.sorted();
            }();
            return table;
        }

        std::mutex &customMutex() {
            static std::mutex m;
            return m;
        }

        std::deque<FieldDef> &customFields() {
            static std::deque<FieldDef> list;
            return list;
        }

        const FieldDef *findBase(std::string_view lowerName) {
            const auto &t = baseTable();
            const auto it = std::lower_bound(t.begin(), t.end(), lowerName,
                                             [](const FieldDef &f, std::string_view n) { return std::string_view(f.name) < n; });
            return (it != t.end() && std::string_view(it->name) == lowerName) ? &*it : nullptr;
        }
    } // namespace

    bool FieldRegistry::add(const FieldDef &field) {
        if (field.name == nullptr || *field.name == '\0' || field.extract == nullptr) {
            problems_.push_back(std::string("incomplete field definition: ") + (field.name ? field.name : "(no name)"));
            return false;
        }
        for (const auto &f: fields_) {
            if (std::string_view(f.name) == field.name) {
                problems_.push_back(std::string("duplicate field name: ") + field.name);
                return false;
            }
        }
        fields_.push_back(field);
        return true;
    }

    std::vector<FieldDef> FieldRegistry::sorted() const {
        std::vector<FieldDef> out = fields_;
        std::sort(out.begin(), out.end(), [](const FieldDef &a, const FieldDef &b) { return std::string_view(a.name) < b.name; });
        return out;
    }

    void initFields() { baseTable(); }

    std::vector<FieldDef> allFields() {
        std::vector<FieldDef> all = baseTable();
        {
            std::lock_guard<std::mutex> lock(customMutex());
            all.insert(all.end(), customFields().begin(), customFields().end());
        }
        std::sort(all.begin(), all.end(), [](const FieldDef &a, const FieldDef &b) { return std::string_view(a.name) < b.name; });
        return all;
    }

    std::vector<FieldDef> builtinFields() { return baseTable(); }

    bool registerField(FieldDef field) {
        if (field.name == nullptr || *field.name == '\0' || field.extract == nullptr) return false;
        const std::string_view name = field.name;
        if (findBase(name) != nullptr) return false;
        std::lock_guard<std::mutex> lock(customMutex());
        for (const auto &f: customFields()) {
            if (std::string_view(f.name) == name) return false;
        }
        customFields().push_back(field);
        return true;
    }

    const FieldDef *findField(std::string_view lowerName) {
        if (const FieldDef *f = findBase(lowerName)) return f;
        std::lock_guard<std::mutex> lock(customMutex());
        for (const auto &f: customFields()) {
            if (std::string_view(f.name) == lowerName) return &f;
        }
        return nullptr;
    }
} // namespace filter
