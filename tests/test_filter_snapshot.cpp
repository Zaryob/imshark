// The oracle for the field-registration refactor (B4): a snapshot of the whole filter field table - name, type,
// description - and of the values every field yields on a fixed set of packets (the sample and corpus captures plus a
// deterministic set of synthetic packets that exercises the gates of the extractors). The snapshot was recorded from the
// table as it was BEFORE the fields moved next to their protocols; it must keep passing unchanged. A deliberate change
// of a field is recorded with IMSHARK_UPDATE_SNAPSHOT=1 (and shows up in review as a diff of the snapshot file).
// Deliberate change (B8): the descriptions of eth.src/eth.dst/eth.addr now say that they cover every Ethernet frame when the
// capture's address table is in the Context. Their values on these packets (no table here) and every digest are unchanged.
// Added (B8): usb.endpoint (the endpoint address of a USB transfer); no other line changed.
#include <gtest/gtest.h>

#include <algorithm>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <sstream>

#include <core.h>
#include <filter/fields.h>

namespace {
    struct Fnv {
        uint64_t h = 1469598103934665603ull;
        void byte(uint8_t b) { h = (h ^ b) * 1099511628211ull; }
        void u64(uint64_t v) { for (int i = 0; i < 8; ++i) byte(static_cast<uint8_t>(v >> (8 * i))); }
        void str(std::string_view s) { u64(s.size()); for (char c: s) byte(static_cast<uint8_t>(c)); }
    };

    struct Rng {
        uint64_t s = 0x9E3779B97F4A7C15ull;
        uint64_t next() { s ^= s << 13; s ^= s >> 7; s ^= s << 17; return s; }
        template<typename T, size_t N>
        const T &pick(const T (&a)[N]) { return a[next() % N]; }
    };

    std::vector<packet::PacketInfo> syntheticPackets() {
        static const char *const kProtocols[] = {
            "", "TCP", "UDP", "0x", "802.11", "AH", "ARP", "ATT", "BGP", "BT Mon", "CHAP", "DCERPC", "DHCP", "DNP3", "DNS", "DTLS",
            "EAP", "EAPOL", "ERSPAN", "ESP", "FTP", "FTP-DATA", "GRE", "HCI", "HTTP", "HTTP2", "ICMP", "ICMPv6", "IGMP", "IKEv2",
            "IP-in-IP", "IPCP", "IPv6CP", "ISAKMP", "Kerberos", "L2CAP", "LACP", "LCP", "LDAP", "LLC", "LLDP", "MAC Control",
            "MDNS", "MPLS", "MSTP", "Malformed", "Mount", "MySQL", "NFS", "NFSv4", "NTP", "OSPF", "PAP", "PGSQL", "PPP", "PPPoED",
            "PPPoES", "Portmap", "RARP", "RPC", "RSTP", "SCTP", "SMB2", "SMTP", "SNAP", "SNMP", "SSH", "STP", "TDS", "TFTP",
            "TLS", "Telnet", "UDP-Lite", "USB", "WLAN", "Modbus", "S7", "SIP", "RTP"};
        static const char *const kText[] = {"", "", "10.0.0.1", "example.org", "a\nb", "EXAMPLE\nrealm", "1.3.6.1.4.1.1466.20037", "SELECT 1", "aa:bb:cc:dd:ee:ff", "x"};
        static const char *const kAddr[] = {"", "10.0.0.1", "10.0.0.2", "192.168.1.5", "2001:db8::1", "fe80::1", "aa:bb:cc:dd:ee:ff", "00:11:22:33:44:55", "0x0040", "hci0", "host", "1.4", "bad"};
        static const char *const kInfo[] = {"", "GET / HTTP/1.1", "[Malformed Packet: x]", "Standard query"};
        static const uint32_t kNum[] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 16, 17, 18, 30, 32, 50, 51, 64, 89, 132, 136, 0x100, 0x200, 0x400, 0xFF, 0x1234, 0x8021, 0xc021, 0xFFFF, 0x0800, 0x86DD, 0x8847, 0x8848, 0x88CC, 0x8808, 0x8863, 0x8864, 0x888E, 0x6558, 0x880B, 1500, 1501, 0x80000000u, 0xFFFFFFFFu};
        static const uint32_t kLink[] = {1, 9, 105, 113, 187, 189, 220, 249, 254, 0, 101};
        Rng r;
        std::vector<packet::PacketInfo> out;
        for (int i = 0; i < 12000; ++i) {
            packet::PacketInfo p(i + 1);
            p.time = static_cast<double>(r.next() % 100000) / 8.0;
            p.protocol = r.pick(kProtocols);
            p.source = r.pick(kAddr);
            p.destination = r.pick(kAddr);
            p.info = r.pick(kInfo);
            p.app_text = r.pick(kText);
            p.app_text2 = r.pick(kText);
            if (r.next() % 3 == 0) p.vlan_ids.push_back(static_cast<uint16_t>(r.pick(kNum)));
            if (r.next() % 5 == 0) p.vlan_ids.push_back(static_cast<uint16_t>(r.pick(kNum)));
            p.link_type = r.pick(kLink);
            p.length = static_cast<uint32_t>(r.pick(kNum));
            p.captured_length = static_cast<uint32_t>(r.pick(kNum));
            p.frame_length = static_cast<uint32_t>(r.pick(kNum));
            p.tcp_pdu_start = r.pick(kNum);
            p.tcp_pdu_len = r.pick(kNum);
            p.app_stream = r.pick(kNum);
            p.tcp_len = r.pick(kNum);
            p.reassembled_in = r.pick(kNum);
            p.ip_id = r.pick(kNum);
            p.has_llc = r.next() % 4 == 0;
            p.has_snap = r.next() % 6 == 0;
            p.has_gre = r.next() % 6 == 0;
            p.has_ipip = r.next() % 6 == 0;
            p.tcp_analysis = static_cast<uint16_t>(r.next());
            p.ether_type = static_cast<uint16_t>(r.pick(kNum));
            p.src_port = static_cast<uint16_t>(r.pick(kNum));
            p.dst_port = static_cast<uint16_t>(r.pick(kNum));
            // the four 16-bit slots of the union, read as whichever view an extractor takes
            p.wlan_fc = static_cast<uint16_t>(r.pick(kNum));
            p.wlan_seq = static_cast<uint16_t>(r.pick(kNum));
            p.radiotap_freq = static_cast<uint16_t>(r.pick(kNum));
            p.ppi_dlt = static_cast<uint16_t>(r.pick(kNum));
            p.app_type = static_cast<uint16_t>(r.pick(kNum));
            p.app_flags = static_cast<uint16_t>(r.pick(kNum));
            p.app_code = static_cast<uint16_t>(r.pick(kNum));
            p.tcp_dup_ack = static_cast<uint8_t>(r.next());
            const uint32_t proto[] = {0, 1, 2, 4, 6, 17, 41, 50, 51, 58, 89, 132, 136};
            p.ip_protocol = static_cast<uint8_t>(r.pick(proto));
            p.ttl = static_cast<uint8_t>(r.next());
            p.tcp_flags = static_cast<uint8_t>(r.next());
            p.radiotap_signal = static_cast<int8_t>(r.next());
            p.radiotap_rate = r.next() & 127;
            p.has_comment = r.next() & 1;
            p.fcs_length = r.next() & 15;
            p.tcp_pdu_state = r.next() & 7;
            p.checksum_state = r.next() & 15;
            p.ip_frag = r.next() % 3;
            const uint32_t versions[] = {0, 4, 4, 6, 6};
            p.ip_version = r.pick(versions);
            out.push_back(std::move(p));
        }
        return out;
    }

    std::string snapshotPath() { return std::string(IMSHARK_TEST_DATA_DIR) + "/filter_fields.snapshot"; }

    const char *typeName(filter::FieldType t) {
        switch (t) {
            case filter::FieldType::Unsigned: return "unsigned";
            case filter::FieldType::Boolean: return "boolean";
            case filter::FieldType::Float: return "float";
            case filter::FieldType::String: return "string";
            case filter::FieldType::Ipv4: return "ipv4";
            case filter::FieldType::Ipv6: return "ipv6";
        }
        return "?";
    }

    std::vector<packet::PacketInfo> allPackets() {
        std::vector<packet::PacketInfo> packets;
        std::vector<std::filesystem::path> files{std::string(IMSHARK_TEST_DATA_DIR) + "/sample.pcap"};
        std::vector<std::filesystem::path> corpus;
        for (const auto &e: std::filesystem::directory_iterator(std::string(IMSHARK_TEST_DATA_DIR) + "/../corpus")) {
            const auto ext = e.path().extension().string();
            if (ext == ".pcap" || ext == ".pcapng") corpus.push_back(e.path());
        }
        std::sort(corpus.begin(), corpus.end());
        files.insert(files.end(), corpus.begin(), corpus.end());
        for (const auto &f: files) {
            core::FileProcessor fp;
            std::vector<packet::PacketInfo> loaded;
            std::string message;
            fp.processFile(f.string(), loaded, message); // a corpus file that is meant to fail to load just yields no packets
            for (auto &p: loaded) packets.push_back(std::move(p));
        }
        for (auto &p: syntheticPackets()) packets.push_back(std::move(p));
        return packets;
    }

    // One line per field: name, type, description, number of packets with a value, number of values, digest of all values.
    std::string buildSnapshot() {
        const auto packets = allPackets();
        std::ostringstream out;
        for (const auto &f: filter::builtinFields()) {
            Fnv h;
            size_t matched = 0, values = 0;
            filter::Context ctx;
            ctx.captureStartEpoch = 1700000000.0;
            for (size_t i = 0; i < packets.size(); ++i) {
                ctx.previous = i ? &packets[i - 1] : nullptr;
                filter::Values v;
                f.extract(packets[i], ctx, v);
                if (v.n > 0) ++matched;
                values += static_cast<size_t>(v.n);
                h.u64(static_cast<uint64_t>(v.n));
                for (int k = 0; k < v.n; ++k) {
                    switch (f.type) {
                        case filter::FieldType::Unsigned:
                        case filter::FieldType::Boolean: h.u64(v.v[k].u); break;
                        case filter::FieldType::Float: { uint64_t bits; std::memcpy(&bits, &v.v[k].d, 8); h.u64(bits); break; }
                        case filter::FieldType::String: h.str(v.v[k].s); break;
                        case filter::FieldType::Ipv4:
                        case filter::FieldType::Ipv6: h.byte(v.v[k].a.v6); for (uint8_t b: v.v[k].a.bytes) h.byte(b); break;
                    }
                }
            }
            char digest[17];
            std::snprintf(digest, sizeof digest, "%016llx", static_cast<unsigned long long>(h.h));
            out << f.name << '\t' << typeName(f.type) << '\t' << f.description << '\t' << matched << '\t' << values << '\t' << digest << '\n';
        }
        return out.str();
    }
}

TEST(FilterSnapshot, FieldTableAndValuesAreUnchanged) {
    const std::string actual = buildSnapshot();
    if (const char *update = std::getenv("IMSHARK_UPDATE_SNAPSHOT"); update && *update && std::string(update) != "0") {
        std::ofstream(snapshotPath(), std::ios::binary) << actual;
    }
    std::ifstream in(snapshotPath(), std::ios::binary);
    ASSERT_TRUE(in) << snapshotPath() << " is missing; run with IMSHARK_UPDATE_SNAPSHOT=1";
    std::ostringstream ss;
    ss << in.rdbuf();
    const std::string expected = ss.str();

    std::istringstream a(actual), e(expected);
    std::string la, le;
    int line = 0;
    while (true) {
        const bool ha = static_cast<bool>(std::getline(a, la)), he = static_cast<bool>(std::getline(e, le));
        ++line;
        if (!ha && !he) break;
        ASSERT_TRUE(ha && he) << "line " << line << ": the field table has " << (ha ? "more" : "fewer") << " fields than the snapshot; extra: " << (ha ? la : le);
        ASSERT_EQ(la, le) << "line " << line;
    }
}

TEST(FilterSnapshot, SnapshotCoversTheTableAndSomethingMatches) {
    // guard against a vacuous oracle: most fields must yield a value on the packet set
    const std::string s = buildSnapshot();
    size_t fields = 0, silent = 0;
    std::istringstream in(s);
    for (std::string line; std::getline(in, line);) {
        ++fields;
        std::vector<std::string> cols;
        std::istringstream ls(line);
        for (std::string c; std::getline(ls, c, '\t');) cols.push_back(c);
        ASSERT_EQ(cols.size(), 6u) << line;
        if (cols[3] == "0") ++silent;
    }
    EXPECT_GE(fields, 370u);
    EXPECT_LE(silent * 20, fields) << silent << " of " << fields << " fields never produce a value on the snapshot packets";
}
