#include "registry.h"

#include "protocols.h"

const dissect::Registry &dissect::Registry::builtin() {
    static const Registry registry = [] {
        Registry r;
        // network layer, by EtherType
        r.registerEtherType(0x0800, dissectIPv4);
        r.registerEtherType(0x86DD, dissectIPv6);
        r.registerEtherType(0x0806, [](Context &c, const char *d, size_t n) { dissectArp(c, d, n, false); });
        r.registerEtherType(0x8035, [](Context &c, const char *d, size_t n) { dissectArp(c, d, n, true); });

        // transport layer, by IP protocol number
        r.registerIpProtocol(1, [](Context &c, const char *d, size_t n) { dissectIcmp(c, d, n, false); });
        r.registerIpProtocol(58, [](Context &c, const char *d, size_t n) { dissectIcmp(c, d, n, true); });
        r.registerIpProtocol(6, dissectTcp);
        r.registerIpProtocol(17, dissectUdp);

        // application layer, recognised by content when no port matched
        r.registerTcpStreamHeuristic({"HTTP", frameHttp, [](Context &c, const char *d, size_t n) { dissectHttp(c, d, n); }});
        r.registerTcpStreamHeuristic({"TLS", frameTls, [](Context &c, const char *d, size_t n) { dissectTls(c, d, n); }});
        r.registerTcpStreamHeuristic({"HTTP2", frameHttp2, dissectHttp2});
        r.registerTcpHeuristic(dissectHttp);
        r.registerTcpHeuristic(dissectTls);
        r.registerTcpHeuristic(dissectHttp2Heuristic);
        r.registerTcpStreamHeuristic({"DNS", frameDnsTcpHeuristic, dissectDnsTcp});   // after HTTP and TLS: it only claims streams that parse as DNS
        r.registerUdpHeuristic(dissectDnsHeuristic);

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
        r.registerUdpPort(53, dissectDns);
        r.registerUdpPort(5353, dissectMdns);
        r.registerUdpPort(67, dissectDhcp);
        r.registerUdpPort(68, dissectDhcp);
        r.registerUdpPort(69, dissectTftp);
        r.registerUdpPort(123, dissectNtp);
        r.registerUdpPort(161, dissectSnmp);
        r.registerUdpPort(162, dissectSnmp);
        // names for Decode As
        auto both = [&](const char *name, Dissector udp, Dissector tcp, std::shared_ptr<StreamProtocol> stream = nullptr) { r.registerProtocolName(name, {std::move(udp), std::move(tcp), std::move(stream)}); };
        both("DNS", dissectDns, dissectDnsTcp, std::make_shared<StreamProtocol>(StreamProtocol{"DNS", frameDnsTcp, dissectDnsTcp}));
        both("MDNS", dissectMdns, nullptr);
        both("DHCP", dissectDhcp, nullptr);
        both("NTP", dissectNtp, nullptr);
        both("SNMP", dissectSnmp, nullptr);
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
