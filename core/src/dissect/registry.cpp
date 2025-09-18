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
        r.registerTcpHeuristic(dissectHttp);
        r.registerTcpHeuristic(dissectTls);

        // application layer, by well-known port
        r.registerTcpPort(23, dissectTelnet);
        r.registerTcpPort(53, dissectDnsTcp);
        r.registerTcpStream(53, {"DNS", frameDnsTcp, dissectDnsTcp});
        r.registerTcpPort(25, dissectSmtp);
        r.registerTcpPort(179, dissectBgp);
        r.registerUdpPort(53, dissectDns);
        r.registerUdpPort(5353, dissectMdns);
        r.registerUdpPort(67, dissectDhcp);
        r.registerUdpPort(68, dissectDhcp);
        r.registerUdpPort(123, dissectNtp);
        r.registerUdpPort(161, dissectSnmp);
        r.registerUdpPort(162, dissectSnmp);
        return r;
    }();
    return registry;
}
