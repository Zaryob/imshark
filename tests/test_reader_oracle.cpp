// Behaviour-preservation oracle for the capture file readers (ROADMAP B5).
//
// Every capture of tests/corpus and tests/data, a set of hand built pcap/pcapng/foreign files and every truncated
// prefix of them is loaded through processFile / processPcapFile / processPcapngFile, and what comes out (return
// value, diagnostics text, packet count, per packet file offset / timestamp bits / link type / lengths / FCS / comment
// flag, capture info) is condensed into one line per input. tests/data/reader_oracle.txt holds those lines as
// recorded before the readers moved behind the CaptureFileReader interface; the readers must reproduce them
// unchanged. Regenerate (only on purpose) with IMSHARK_ORACLE_WRITE=<file>.
// Deliberate change (task GX, B5 fix): a pcapng damaged after at least one readable packet used to skip the end of the
// load pass (tables not frozen, capture start 0, so relative times and decoding differed from a complete file); the
// digests of exactly those inputs (damaged pcapng that still yields packets, and the prefix aggregates of pcapng
// files) were regenerated. ok, packet count and message of every line are unchanged; complete files are untouched.
#include <gtest/gtest.h>

#include <algorithm>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <map>
#include <sstream>

#include <core.h>
#include "support.h"

namespace {
    namespace fs = std::filesystem;

    struct Digest {
        uint64_t h = 1469598103934665603ull;
        void add(uint64_t v) {
            for (int i = 0; i < 8; ++i) { h ^= (v >> (8 * i)) & 0xff; h *= 1099511628211ull; }
        }
        void add(const std::string &s) { add(uint64_t(s.size())); for (unsigned char c: s) { h ^= c; h *= 1099511628211ull; } }
        void add(double d) { uint64_t u; std::memcpy(&u, &d, 8); add(u); }
    };

    std::string hex64(uint64_t v) {
        char buf[20];
        std::snprintf(buf, sizeof buf, "%016llx", static_cast<unsigned long long>(v));
        return buf;
    }

    enum class Entry { Auto, Pcap, Pcapng };

    // What loading `path` through `entry` produced, as one digest plus a readable summary.
    std::string load(const std::string &path, Entry entry, bool detailed) {
        core::FileProcessor fp;
        std::vector<packet::PacketInfo> packets;
        std::string message;
        const bool ok = entry == Entry::Auto ? fp.processFile(path, packets, message)
                      : entry == Entry::Pcap ? fp.processPcapFile(path, packets, message)
                                             : fp.processPcapngFile(path, packets, message);
        Digest d;
        d.add(uint64_t(ok));
        d.add(message);
        d.add(uint64_t(packets.size()));
        for (const auto &p: packets) {
            d.add(uint64_t(p.number));
            d.add(p.file_offset);
            d.add(p.time);
            d.add(uint64_t(p.link_type));
            d.add(uint64_t(p.captured_length));
            d.add(uint64_t(p.frame_length));
            d.add(uint64_t(p.fcs_length));
            d.add(uint64_t(p.has_comment));
            d.add(p.protocol);
            d.add(p.info);
        }
        const auto &info = fp.captureInfo();
        d.add(fp.captureStartEpoch());
        d.add(info.format);
        d.add(info.fileSize);
        d.add(uint64_t(info.sections));
        d.add(info.comment); d.add(info.hardware); d.add(info.os); d.add(info.application);
        for (const auto &i: info.interfaces) {
            d.add(uint64_t(i.linkType)); d.add(uint64_t(i.snapLen)); d.add(i.ticksPerSecond); d.add(i.name); d.add(i.description);
            d.add(i.packets); d.add(uint64_t(i.hasStats)); d.add(i.received); d.add(i.dropped); d.add(uint64_t(i.fcsLength));
        }
        for (const auto &n: info.names) { d.add(n.address); d.add(n.name); }
        const std::map<uint32_t, std::string> comments(info.packetComments.begin(), info.packetComments.end());
        for (const auto &[n, c]: comments) { d.add(uint64_t(n)); d.add(c); }
        for (const auto &s: info.decryptionSecrets) { d.add(uint64_t(s.type)); d.add(s.data); }
        d.add(uint64_t(info.tlsKeyLogSecrets)); d.add(uint64_t(info.tlsKeyLogMalformed)); d.add(uint64_t(info.tlsKeyLogDropped));

        std::ostringstream out;
        out << "ok=" << ok << " n=" << packets.size() << " digest=" << hex64(d.h);
        if (detailed) {
            out << " fmt=\"" << info.format << "\" ifaces=" << info.interfaces.size() << " msg=\"" << message << "\"";
        }
        return out.str();
    }

    std::vector<char> readAll(const fs::path &p) {
        std::ifstream f(p, std::ios::binary);
        return std::vector<char>((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
    }

    // ---- hand built files ---------------------------------------------------------------------------------
    std::vector<char> frame(size_t n, uint8_t seed) {
        std::vector<char> f(n);
        for (size_t i = 0; i < n; ++i) f[i] = static_cast<char>(seed + i);
        if (n >= 14) { f[12] = 0x08; f[13] = 0x00; } // IPv4 ethertype
        return f;
    }

    std::vector<char> pcapFile(bool be, uint32_t magic, uint32_t network, const std::vector<std::pair<uint32_t, size_t>> &recs) {
        std::vector<char> b;
        support::put<uint32_t>(b, magic, be);
        support::put<uint16_t>(b, 2, be); support::put<uint16_t>(b, 4, be);
        support::put<uint32_t>(b, 0, be); support::put<uint32_t>(b, 0, be);
        support::put<uint32_t>(b, 65535, be); support::put<uint32_t>(b, network, be);
        uint32_t ts = 1000;
        for (const auto &[frac, len]: recs) {
            support::put<uint32_t>(b, ts++, be); support::put<uint32_t>(b, frac, be);
            support::put<uint32_t>(b, uint32_t(len), be); support::put<uint32_t>(b, uint32_t(len + 4), be);
            const auto f = frame(len, uint8_t(ts));
            b.insert(b.end(), f.begin(), f.end());
        }
        return b;
    }

    struct Ng {
        bool be;
        std::vector<char> out;
        void block(uint32_t type, const std::vector<char> &body) {
            const uint32_t total = uint32_t(12 + ((body.size() + 3) & ~size_t(3)));
            support::put<uint32_t>(out, type, be); support::put<uint32_t>(out, total, be);
            out.insert(out.end(), body.begin(), body.end());
            out.insert(out.end(), total - 12 - body.size(), 0);
            support::put<uint32_t>(out, total, be);
        }
        void option(std::vector<char> &o, uint16_t code, const std::string &v) {
            support::put<uint16_t>(o, code, be); support::put<uint16_t>(o, uint16_t(v.size()), be);
            o.insert(o.end(), v.begin(), v.end());
            o.insert(o.end(), (4 - v.size() % 4) % 4, 0);
        }
        void end(std::vector<char> &o) { support::put<uint32_t>(o, 0, be); }
    };

    std::vector<char> richPcapng(bool be) {
        Ng ng{be, {}};
        { // SHB with options
            std::vector<char> b;
            support::put<uint32_t>(b, 0x1A2B3C4D, be); support::put<uint16_t>(b, 1, be); support::put<uint16_t>(b, 0, be);
            support::put<uint64_t>(b, ~0ull, be);
            ng.option(b, 1, "section comment"); ng.option(b, 2, "hw"); ng.option(b, 3, "os"); ng.option(b, 4, "app"); ng.end(b);
            ng.block(0x0A0D0D0A, b);
        }
        { // IDB 0: ethernet, nanoseconds, fcs 32 bits, tsoffset 5
            std::vector<char> b;
            support::put<uint16_t>(b, 1, be); support::put<uint16_t>(b, 0, be); support::put<uint32_t>(b, 1500, be);
            ng.option(b, 2, "eth0"); ng.option(b, 3, "first");
            ng.option(b, 9, std::string(1, char(9)));
            ng.option(b, 13, std::string(1, char(32)));
            std::string off(8, 0); off[be ? 7 : 0] = 5; ng.option(b, 14, off);
            ng.end(b);
            ng.block(1, b);
        }
        { // IDB 1: linux cooked, default resolution
            std::vector<char> b;
            support::put<uint16_t>(b, 113, be); support::put<uint16_t>(b, 0, be); support::put<uint32_t>(b, 96, be);
            ng.end(b);
            ng.block(1, b);
        }
        auto epb = [&](uint32_t itf, uint64_t ticks, size_t len, const std::string &comment) {
            std::vector<char> b;
            support::put<uint32_t>(b, itf, be);
            support::put<uint32_t>(b, uint32_t(ticks >> 32), be); support::put<uint32_t>(b, uint32_t(ticks), be);
            support::put<uint32_t>(b, uint32_t(len), be); support::put<uint32_t>(b, uint32_t(len + 10), be);
            const auto f = frame(len, uint8_t(itf + len));
            b.insert(b.end(), f.begin(), f.end());
            b.insert(b.end(), (4 - len % 4) % 4, 0);
            if (!comment.empty()) { ng.option(b, 1, comment); }
            ng.end(b);
            ng.block(6, b);
        };
        epb(0, 1'500'000'123ull, 60, "first packet");
        epb(1, 2'000'123ull, 40, "");
        epb(0, 1'600'000'000ull, 33, "odd length");
        epb(7, 3, 20, "");            // undefined interface
        { // SPB
            std::vector<char> b;
            support::put<uint32_t>(b, 50, be);
            const auto f = frame(50, 3);
            b.insert(b.end(), f.begin(), f.end());
            b.insert(b.end(), 2, 0);
            ng.block(3, b);
        }
        { // obsolete PB
            std::vector<char> b;
            support::put<uint16_t>(b, 0, be); support::put<uint16_t>(b, 0, be);
            support::put<uint32_t>(b, 0, be); support::put<uint32_t>(b, 2'000'000, be);
            support::put<uint32_t>(b, 30, be); support::put<uint32_t>(b, 30, be);
            const auto f = frame(30, 9);
            b.insert(b.end(), f.begin(), f.end());
            b.insert(b.end(), 2, 0);
            ng.block(2, b);
        }
        { // NRB
            std::vector<char> b;
            support::put<uint16_t>(b, 1, be); support::put<uint16_t>(b, 12, be);
            b.insert(b.end(), {10, 0, 0, 1, 'h', 'o', 's', 't', 0, 'x', 0, 0});
            support::put<uint16_t>(b, 0, be); support::put<uint16_t>(b, 0, be);
            ng.block(4, b);
        }
        { // ISB
            std::vector<char> b;
            support::put<uint32_t>(b, 0, be); support::put<uint32_t>(b, 0, be); support::put<uint32_t>(b, 0, be);
            std::string v(8, 0); v[be ? 7 : 0] = 42;
            ng.option(b, 4, v); ng.option(b, 5, v); ng.end(b);
            ng.block(5, b);
        }
        { // DSB with a TLS key log
            const std::string log = "CLIENT_RANDOM 0000000000000000000000000000000000000000000000000000000000000001 "
                                    "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\nbad line\n";
            std::vector<char> b;
            support::put<uint32_t>(b, 0x544c534b, be); support::put<uint32_t>(b, uint32_t(log.size()), be);
            b.insert(b.end(), log.begin(), log.end());
            b.insert(b.end(), (4 - log.size() % 4) % 4, 0);
            ng.block(0x0A, b);
        }
        { // unknown block, then a second section
            ng.block(0x40000001, {1, 2, 3, 4});
            std::vector<char> b;
            support::put<uint32_t>(b, 0x1A2B3C4D, be); support::put<uint16_t>(b, 1, be); support::put<uint16_t>(b, 0, be);
            support::put<uint64_t>(b, ~0ull, be); ng.end(b);
            ng.block(0x0A0D0D0A, b);
            std::vector<char> idb;
            support::put<uint16_t>(idb, 1, be); support::put<uint16_t>(idb, 0, be); support::put<uint32_t>(idb, 0, be);
            ng.block(1, idb);
            epb(0, 5, 24, "second section");
        }
        return ng.out;
    }

    std::vector<std::pair<std::string, std::vector<char>>> syntheticInputs() {
        std::vector<std::pair<std::string, std::vector<char>>> v;
        v.emplace_back("empty", std::vector<char>{});
        v.emplace_back("three-bytes", std::vector<char>{'a', 'b', 'c'});
        v.emplace_back("garbage-32", std::vector<char>(32, 'x'));
        v.emplace_back("zeros-64", std::vector<char>(64, 0));
        v.emplace_back("pcap-le-micro", pcapFile(false, 0xa1b2c3d4, 1, {{1, 60}, {999999, 14}, {5, 0}, {7, 100}}));
        v.emplace_back("pcap-be-micro", pcapFile(true, 0xa1b2c3d4, 1, {{1, 60}, {2, 20}}));
        v.emplace_back("pcap-le-nano", pcapFile(false, 0xa1b23c4d, 1, {{1, 60}, {999999999, 14}}));
        v.emplace_back("pcap-be-nano", pcapFile(true, 0xa1b23c4d, 1, {{1, 60}}));
        v.emplace_back("pcap-fcs-bits", pcapFile(false, 0xa1b2c3d4, 0x50000001, {{1, 60}, {2, 61}}));
        v.emplace_back("pcap-cooked", pcapFile(false, 0xa1b2c3d4, 113, {{1, 40}}));
        v.emplace_back("pcap-header-only", pcapFile(false, 0xa1b2c3d4, 1, {}));
        v.emplace_back("pcapng-le-rich", richPcapng(false));
        v.emplace_back("pcapng-be-rich", richPcapng(true));
        {   // oversized record length
            auto b = pcapFile(false, 0xa1b2c3d4, 1, {{1, 60}});
            b[24 + 8] = char(0xff); b[24 + 9] = char(0xff); b[24 + 10] = char(0xff); b[24 + 11] = char(0x7f);
            v.emplace_back("pcap-huge-caplen", b);
        }
        {   // pcapng bad block length / bad trailing length / not starting with an SHB
            auto b = richPcapng(false);
            auto c = b; c[24 + 4] = char(0x03);
            v.emplace_back("pcapng-bad-total-length", c);
            auto d = b; d[d.size() - 1] = char(0x7e);
            v.emplace_back("pcapng-bad-trailer", d);
            std::vector<char> e(b.begin() + 28, b.end());
            v.emplace_back("pcapng-no-shb", e);
            auto f = b; f[8] = 0; f[9] = 0; f[10] = 0; f[11] = 0;
            v.emplace_back("pcapng-bad-byte-order", f);
        }
        v.emplace_back("netmon", std::vector<char>{'G', 'M', 'B', 'U', 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0});
        v.emplace_back("snoop", std::vector<char>{'s', 'n', 'o', 'o', 'p', 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0});
        v.emplace_back("iptrace", std::vector<char>{'i', 'p', 't', 'r', 'a', 'c', 'e', ' ', '2', '.', '0', 0, 0, 0, 0, 0, 0, 0, 0, 0});
        {
            std::vector<char> erf(64, 0);
            erf[8] = 2; erf[11] = 64; erf[15] = 60;
            v.emplace_back("erf", erf);
        }
        v.emplace_back("gzip", std::vector<char>{char(0x1f), char(0x8b), 8, 0, 0, 0, 0, 0, 0, 3, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0});
        return v;
    }
} // namespace

TEST(ReaderOracle, ReadersReproduceTheRecordedBehaviour) {
    const fs::path data = IMSHARK_TEST_DATA_DIR;
    std::vector<std::pair<std::string, std::vector<char>>> inputs;
    std::vector<fs::path> files;
    for (const auto &e: fs::directory_iterator(data / ".." / "corpus")) {
        const auto ext = e.path().extension().string();
        if (ext == ".pcap" || ext == ".pcapng") files.push_back(e.path());
    }
    std::sort(files.begin(), files.end());
    files.push_back(data / "sample.pcap");
    for (const auto &p: files) inputs.emplace_back(p.filename().string(), readAll(p));
    for (auto &s: syntheticInputs()) inputs.push_back(std::move(s));

    std::ostringstream actual;
    const struct { const char *name; Entry entry; } entries[] = {{"auto", Entry::Auto}, {"pcap", Entry::Pcap}, {"pcapng", Entry::Pcapng}};
    for (const auto &[name, bytes]: inputs) {
        const auto path = support::writeTemp("oracle.bin", bytes);
        for (const auto &en: entries) actual << name << " " << en.name << " " << load(path, en.entry, true) << "\n";
        // every prefix: no crash, and the aggregate of all results is stable
        Digest all;
        size_t prefixes = 0;
        for (size_t n = 0; n < bytes.size(); n += (bytes.size() > 400 ? 3 : 1)) {
            const auto cut = support::writeTemp("oracle_cut.bin", std::vector<char>(bytes.begin(), bytes.begin() + n));
            for (const auto &en: entries) all.add(load(cut, en.entry, true));
            ++prefixes;
            std::remove(cut.c_str());
        }
        actual << name << " prefixes " << prefixes << " digest=" << hex64(all.h) << "\n";
        std::remove(path.c_str());
    }

    if (const char *out = std::getenv("IMSHARK_ORACLE_WRITE")) {
        std::ofstream(out, std::ios::binary) << actual.str();
        GTEST_SKIP() << "oracle written to " << out;
    }
    const auto expected = readAll(data / "reader_oracle.txt");
    const std::string want(expected.begin(), expected.end());
    // compare line by line so a failure names the input
    std::istringstream a(actual.str()), w(want);
    std::string la, lw;
    int line = 0;
    while (true) {
        const bool ga = static_cast<bool>(std::getline(a, la)), gw = static_cast<bool>(std::getline(w, lw));
        if (!ga && !gw) break;
        ++line;
        EXPECT_EQ(ga ? la : "<missing>", gw ? lw : "<missing>") << "line " << line;
    }
}
