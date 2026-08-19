#include "registry.h"

#include "protocols.h"
#include "igmp.h"
#include "sctp.h"
#include "ospf.h"
#include "ipsec.h"
#include "ldap.h"
#include "kerberos.h"
#include "smb2.h"
#include "dcerpc.h"
#include "nfs.h"
#include "postgres.h"
#include "mysql.h"
#include "tds.h"
#include "usb.h"
#include "bluetooth.h"
#include "voip.h"
#include "industrial.h"

const dissect::Registry &dissect::Registry::builtin() {
    static const Registry registry = [] {
        Registry r;
        // link layer, by LinkType
        r.registerLinkType(9, dissectPpp);
        r.registerLinkType(105, dissectIeee80211);
        r.registerLinkType(127, dissectRadiotap);
        r.registerLinkType(192, dissectPpi);
        r.registerLinkType(189, dissectUsbLinux);
        r.registerLinkType(220, dissectUsbLinuxMmapped);
        r.registerLinkType(249, dissectUsbPcap);
        r.registerLinkType(187, dissectBluetoothHciH4);
        r.registerLinkType(254, dissectBluetoothLinuxMonitor);
        r.registerLinkType(195, dissectIeee802154WithFcs);
        r.registerLinkType(215, dissectIeee802154NonaskPhy);
        r.registerLinkType(230, dissectIeee802154);
        r.registerLinkType(227, dissectSocketCan);

        // network layer, by EtherType
        r.registerEtherType(0x0800, dissectIPv4);
        r.registerEtherType(0x86DD, dissectIPv6);
        r.registerEtherType(0x0806, [](Context &c, const char *d, size_t n) { dissectArp(c, d, n, false); });
        r.registerEtherType(0x8035, [](Context &c, const char *d, size_t n) { dissectArp(c, d, n, true); });
        r.registerEtherType(0x8847, dissectMpls);
        r.registerEtherType(0x8848, dissectMpls);
        r.registerEtherType(0x8863, dissectPppoeDiscovery);
        r.registerEtherType(0x8864, dissectPppoeSession);
        r.registerEtherType(0x888E, dissectEapol);
        r.registerEtherType(0x88CC, dissectLldp);
        r.registerEtherType(0x8809, dissectSlowProtocols);
        r.registerEtherType(0x8808, dissectEthernetControl);

        // transport layer, by IP protocol number
        r.registerIpProtocol(1, [](Context &c, const char *d, size_t n) { dissectIcmp(c, d, n, false); });
        r.registerIpProtocol(2, dissectIgmp);
        r.registerIpProtocol(58, [](Context &c, const char *d, size_t n) { dissectIcmp(c, d, n, true); });
        r.registerIpProtocol(6, dissectTcp);
        r.registerIpProtocol(17, dissectUdp);
        r.registerIpProtocol(50, dissectEsp);
        r.registerIpProtocol(51, dissectAh);
        r.registerIpProtocol(89, dissectOspf);
        r.registerIpProtocol(132, dissectSctp);
        r.registerIpProtocol(136, dissectUdpLite);
        r.registerIpProtocol(4, dissectIpInIp);
        r.registerIpProtocol(41, dissectIpInIp);
        r.registerIpProtocol(47, dissectGre);

        // application layer, recognised by content when no port matched
        r.registerTcpStreamHeuristic({"HTTP", frameHttp, [](Context &c, const char *d, size_t n) { dissectHttp(c, d, n); }});
        r.registerTcpStreamHeuristic({"TLS", frameTls, [](Context &c, const char *d, size_t n) { dissectTls(c, d, n); }});
        r.registerTcpStreamHeuristic({"HTTP2", frameHttp2, dissectHttp2});
        r.registerTcpHeuristic(dissectHttp);
        r.registerTcpHeuristic(dissectTls);
        r.registerTcpHeuristic(dissectHttp2Heuristic);
        r.registerTcpStreamHeuristic({"DNS", frameDnsTcpHeuristic, dissectDnsTcp});   // after HTTP and TLS: it only claims streams that parse as DNS
        r.registerUdpHeuristic(dissectDnsHeuristic);
        r.registerUdpHeuristic(dissectDtlsHeuristic);   // 3478 / 5349 (TURN) and every other port: only a datagram that is nothing but valid DTLS records

        // application layer, by well-known port
        r.registerTcpPort(20, dissectFtpData);
        r.registerTcpPort(21, dissectFtp);
        r.registerTcpPort(22, dissectSsh);
        r.registerTcpPort(23, dissectTelnet);
        r.registerTcpPort(53, dissectDnsTcp);
        r.registerTcpStream(53, {"DNS", frameDnsTcp, dissectDnsTcp});
        r.registerTcpPort(25, dissectSmtp);
        r.registerTcpPort(587, dissectSmtp);
        r.registerTcpPort(179, dissectBgp);
        r.registerTcpStream(179, {"BGP", frameBgp, dissectBgp});
        r.registerTcpPort(389, dissectLdap);
        r.registerTcpStream(389, {"LDAP", frameLdap, dissectLdap});
        r.registerTcpPort(636, dissectLdap);
        r.registerTcpStream(636, {"LDAP", frameLdap, dissectLdap});
        r.registerTcpPort(88, dissectKerberos);
        r.registerTcpStream(88, {"Kerberos", frameKerberos, dissectKerberos});
        r.registerTcpPort(445, dissectSmb2);
        r.registerTcpStream(445, {"SMB2", frameSmb2, dissectSmb2});
        r.registerTcpPort(139, dissectSmb2);
        r.registerTcpStream(139, {"SMB2", frameSmb2, dissectSmb2});
        r.registerTcpPort(135, dissectDceRpc);
        r.registerTcpStream(135, {"DCERPC", frameDceRpc, dissectDceRpc});
        r.registerTcpPort(2049, dissectNfs);
        r.registerTcpStream(2049, {"NFS", frameRpc, dissectNfs});
        r.registerTcpPort(111, dissectNfs);
        r.registerTcpStream(111, {"Portmap", frameRpc, dissectNfs});
        r.registerTcpPort(5432, dissectPostgreSql);
        r.registerTcpStream(5432, {"PGSQL", framePostgreSql, dissectPostgreSql});
        r.registerTcpPort(3306, dissectMySql);
        r.registerTcpStream(3306, {"MySQL", frameMySql, dissectMySql});
        r.registerTcpPort(1433, dissectTds);
        r.registerTcpStream(1433, {"TDS", frameTds, dissectTds});
        r.registerTcpPort(5060, dissectSip);
        r.registerTcpStream(5060, {"SIP", frameSip, dissectSip});
        r.registerTcpPort(554, dissectRtsp);
        r.registerTcpStream(554, {"RTSP", frameRtsp, dissectRtsp});
        r.registerTcpPort(502, dissectModbus);
        r.registerTcpStream(502, {"Modbus", frameModbus, dissectModbus});
        r.registerTcpPort(20000, dissectDnp3);
        r.registerTcpStream(20000, {"DNP3", frameDnp3, dissectDnp3});
        r.registerUdpPort(53, dissectDns);
        r.registerUdpPort(88, dissectKerberos);
        r.registerUdpPort(111, dissectNfs);
        r.registerUdpPort(2049, dissectNfs);
        r.registerUdpPort(5060, dissectSip);
        r.registerUdpPort(20000, dissectDnp3);
        r.registerUdpPort(5353, dissectMdns);
        r.registerUdpPort(67, dissectDhcp);
        r.registerUdpPort(68, dissectDhcp);
        r.registerUdpPort(69, dissectTftp);
        r.registerUdpPort(123, dissectNtp);
        r.registerUdpPort(161, dissectSnmp);
        r.registerUdpPort(162, dissectSnmp);
        r.registerUdpPort(500, dissectIke);
        r.registerUdpPort(4500, dissectIke);
        r.registerUdpPort(4433, dissectDtlsPort);
        r.registerUdpPort(5684, dissectDtlsPort);   // CoAPs
        r.registerUdpPort(9899, [](Context &c, const char *d, size_t n) { if (n >= 12) dissectSctp(c, d, n); });   // SCTP over UDP (RFC 6951); a shorter payload cannot hold a common header: raw UDP
        // names for Decode As
        auto both = [&](const char *name, Dissector udp, Dissector tcp, std::shared_ptr<StreamProtocol> stream = nullptr) { r.registerProtocolName(name, {std::move(udp), std::move(tcp), std::move(stream)}); };
        both("DNS", dissectDns, dissectDnsTcp, std::make_shared<StreamProtocol>(StreamProtocol{"DNS", frameDnsTcp, dissectDnsTcp}));
        both("MDNS", dissectMdns, nullptr);
        both("DHCP", dissectDhcp, nullptr);
        both("NTP", dissectNtp, nullptr);
        both("SNMP", dissectSnmp, nullptr);
        both("LDAP", nullptr, dissectLdap, std::make_shared<StreamProtocol>(StreamProtocol{"LDAP", frameLdap, dissectLdap}));
        both("Kerberos", dissectKerberos, dissectKerberos, std::make_shared<StreamProtocol>(StreamProtocol{"Kerberos", frameKerberos, dissectKerberos}));
        both("SMB2", nullptr, dissectSmb2, std::make_shared<StreamProtocol>(StreamProtocol{"SMB2", frameSmb2, dissectSmb2}));
        both("DCERPC", nullptr, dissectDceRpc, std::make_shared<StreamProtocol>(StreamProtocol{"DCERPC", frameDceRpc, dissectDceRpc}));
        both("NFS", dissectNfs, dissectNfs, std::make_shared<StreamProtocol>(StreamProtocol{"NFS", frameRpc, dissectNfs}));
        both("Portmap", dissectNfs, dissectNfs, std::make_shared<StreamProtocol>(StreamProtocol{"Portmap", frameRpc, dissectNfs}));
        both("PGSQL", nullptr, dissectPostgreSql, std::make_shared<StreamProtocol>(StreamProtocol{"PGSQL", framePostgreSql, dissectPostgreSql}));
        both("MySQL", nullptr, dissectMySql, std::make_shared<StreamProtocol>(StreamProtocol{"MySQL", frameMySql, dissectMySql}));
        both("TDS", nullptr, dissectTds, std::make_shared<StreamProtocol>(StreamProtocol{"TDS", frameTds, dissectTds}));
        both("SIP", dissectSip, dissectSip, std::make_shared<StreamProtocol>(StreamProtocol{"SIP", frameSip, dissectSip}));
        both("RTSP", nullptr, dissectRtsp, std::make_shared<StreamProtocol>(StreamProtocol{"RTSP", frameRtsp, dissectRtsp}));
        both("RTP", dissectRtp, nullptr);
        both("RTCP", dissectRtcp, nullptr);
        both("Modbus", nullptr, dissectModbus, std::make_shared<StreamProtocol>(StreamProtocol{"Modbus", frameModbus, dissectModbus}));
        both("DNP3", dissectDnp3, dissectDnp3, std::make_shared<StreamProtocol>(StreamProtocol{"DNP3", frameDnp3, dissectDnp3}));
        both("DTLS", dissectDtlsPort, nullptr);
        both("SCTP", dissectSctp, nullptr);   // SCTP over UDP (RFC 6951) on another port
        both("HTTP", nullptr, nullptr, std::make_shared<StreamProtocol>(StreamProtocol{"HTTP", frameHttp, [](Context &c, const char *d, size_t n) { dissectHttp(c, d, n); }}));
        both("HTTP2", nullptr, dissectHttp2, std::make_shared<StreamProtocol>(StreamProtocol{"HTTP2", frameHttp2, dissectHttp2}));
        both("TLS", nullptr, nullptr, std::make_shared<StreamProtocol>(StreamProtocol{"TLS", frameTls, [](Context &c, const char *d, size_t n) { dissectTls(c, d, n); }}));
        both("Telnet", nullptr, dissectTelnet);
        both("SMTP", nullptr, dissectSmtp);
        both("FTP", nullptr, dissectFtp);
        both("FTP-DATA", nullptr, dissectFtpData);
        both("TFTP", dissectTftp, nullptr);
        both("SSH", nullptr, dissectSsh);
        both("BGP", nullptr, dissectBgp, std::make_shared<StreamProtocol>(StreamProtocol{"BGP", frameBgp, dissectBgp}));
        return r;
    }();
    return registry;
}

std::vector<std::string> dissect::Registry::protocolNames(bool tcp) const {
    std::vector<std::string> out;
    for (const auto &[name, h]: named_) if (tcp ? (h.tcp || h.stream) : static_cast<bool>(h.udp)) out.push_back(name);
    return out;   // std::map keeps them sorted
}

bool dissect::Registry::decodeAs(bool tcp, uint16_t port, const std::string &protocol, std::string *error) {
    const auto it = named_.find(protocol);
    if (it == named_.end() || !(tcp ? (it->second.tcp || it->second.stream) : static_cast<bool>(it->second.udp))) {
        if (error) *error = "No protocol \"" + protocol + "\" for " + (tcp ? "TCP" : "UDP");
        return false;
    }
    if (port == 0) {
        if (error) *error = "Port 0 cannot be used";
        return false;
    }
    if (tcp) {
        tcpPorts_.erase(port);
        tcpStreams_.erase(port);
        if (it->second.stream) registerTcpStream(port, *it->second.stream);
        else registerTcpPort(port, it->second.tcp);
    } else {
        registerUdpPort(port, it->second.udp);
    }
    return true;
}
