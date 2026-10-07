// The oracle for the statistics generalisation (B8): a text rendering of the endpoints, conversations and protocol
// hierarchy of every capture under tests/ (sample.pcap, tests/corpus, tests/data/tls), recorded before USB endpoints
// and the MAC addresses of IP frames were added. The existing address kinds must keep producing exactly this output.
// A deliberate change is recorded with IMSHARK_UPDATE_SNAPSHOT=1 (and shows up in review as a diff of the file).
#include <gtest/gtest.h>

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <sstream>

#include <core.h>
#include <stats/statistics.h>
#include <tls/crypto.h>

namespace {
    std::string snapshotPath() { return std::string(IMSHARK_TEST_DATA_DIR) + "/stats.snapshot"; }

    std::string num(double v) {
        char buf[48];
        std::snprintf(buf, sizeof(buf), "%.6f", v);
        return buf;
    }

    void hierarchy(std::ostream &out, const stats::HierarchyNode &n, int depth) {
        out << std::string(static_cast<size_t>(depth) * 2, ' ') << n.name << " " << n.packets << " " << n.bytes << "\n";
        for (const auto &c: n.children) hierarchy(out, c, depth + 1);
    }

    std::vector<std::filesystem::path> captureFiles() {
        std::vector<std::filesystem::path> files{std::string(IMSHARK_TEST_DATA_DIR) + "/sample.pcap"};
        std::vector<std::filesystem::path> more;
        for (const char *dir: {"/../corpus", "/tls"}) {
            for (const auto &e: std::filesystem::directory_iterator(std::string(IMSHARK_TEST_DATA_DIR) + dir)) {
                const auto ext = e.path().extension().string();
                if (ext == ".pcap" || ext == ".pcapng" || ext == ".cap" || ext == ".snoop" || ext == ".erf" || ext == ".iptrace") more.push_back(e.path());
            }
        }
        std::sort(more.begin(), more.end());
        files.insert(files.end(), more.begin(), more.end());
        return files;
    }

    std::string buildSnapshot() {
        using stats::AddressKind;
        // the nine kinds that existed when the snapshot was recorded
        const AddressKind kinds[] = {AddressKind::Ipv4, AddressKind::Ipv6, AddressKind::Tcp, AddressKind::Udp, AddressKind::Sctp,
                                     AddressKind::Ethernet, AddressKind::Wlan, AddressKind::Bluetooth, AddressKind::Usb};
        std::ostringstream out;
        for (const auto &file: captureFiles()) {
            core::FileProcessor fp;
            std::vector<packet::PacketInfo> packets;
            std::string message;
            fp.processFile(file.string(), packets, message);
            out << "== " << file.filename().string() << " " << packets.size() << "\n";
            for (AddressKind kind: kinds) {
                out << "-- " << stats::kindName(kind) << "\n";
                for (const auto &e: stats::endpoints(packets, nullptr, kind)) {
                    out << "E " << e.address << " " << e.port << " " << e.packets << " " << e.bytes << " " << e.txPackets << " " << e.txBytes
                        << " " << e.rxPackets << " " << e.rxBytes << " | " << stats::endpointFilter(e, kind) << "\n";
                }
                for (const auto &c: stats::conversations(packets, nullptr, kind)) {
                    out << "C " << c.addressA << " " << c.portA << " " << c.addressB << " " << c.portB << " " << c.packets << " " << c.bytes
                        << " " << c.packetsAtoB << " " << c.bytesAtoB << " " << c.packetsBtoA << " " << c.bytesBtoA << " " << num(c.start)
                        << " " << num(c.duration) << " " << c.firstPacket << " | " << stats::conversationFilter(c, kind) << "\n";
                }
            }
            out << "-- Hierarchy\n";
            hierarchy(out, stats::protocolHierarchy(packets, nullptr), 0);
        }
        return out.str();
    }
} // namespace

TEST(StatsSnapshot, EndpointsConversationsAndHierarchyAreUnchanged) {
    const std::string actual = buildSnapshot();
    if (const char *update = std::getenv("IMSHARK_UPDATE_SNAPSHOT"); update && *update && std::string(update) != "0") {
        std::ofstream(snapshotPath(), std::ios::binary) << actual;
    }
    std::ifstream in(snapshotPath(), std::ios::binary);
    ASSERT_TRUE(in) << snapshotPath() << " is missing; run with IMSHARK_UPDATE_SNAPSHOT=1";
    std::ostringstream ss;
    ss << in.rdbuf();

    // The oracle was recorded with TLS decryption enabled. A build without the
    // crypto backend still checks every endpoint, conversation and outer layer;
    // only descendants of a TLS hierarchy node cannot exist in that build.
    std::string expected = ss.str();
    if (!tls::crypto::available()) {
        std::istringstream lines(expected);
        std::ostringstream outer;
        std::string text;
        size_t tlsIndent = std::string::npos;
        while (std::getline(lines, text)) {
            const size_t indent = text.find_first_not_of(' ');
            if (tlsIndent != std::string::npos && indent > tlsIndent && indent != std::string::npos) continue;
            tlsIndent = text.find("Transport Layer Security ") == indent ? indent : std::string::npos;
            outer << text << '\n';
        }
        expected = outer.str();
    }

    std::istringstream a(actual), e(expected);
    std::string la, le;
    int line = 0;
    while (true) {
        const bool ha = static_cast<bool>(std::getline(a, la)), he = static_cast<bool>(std::getline(e, le));
        ++line;
        if (!ha && !he) break;
        ASSERT_TRUE(ha && he) << "line " << line << ": the statistics have " << (ha ? "more" : "fewer") << " lines than the snapshot; extra: " << (ha ? la : le);
        ASSERT_EQ(la, le) << "line " << line;
    }
}

TEST(StatsSnapshot, SnapshotIsNotVacuous) {
    const std::string s = buildSnapshot();
    EXPECT_NE(s.find("\n-- IPv4\nE "), std::string::npos);
    EXPECT_NE(s.find("\n-- TCP\nE "), std::string::npos);
    EXPECT_NE(s.find("\n-- Ethernet\nE "), std::string::npos);
    EXPECT_NE(s.find("\nC "), std::string::npos);
}
