#pragma once

// Shared helpers for "every field stays inside the frame" tests (R1; reuse them for later dissector tests):
//   framesweep::parseEthernet   parse one frame in Full mode (Ethernet unless another link type is given)
//   framesweep::ethernet / ipv4Packet / ipv6Packet / udpDatagram   hand-built frames (IP header checksum filled in)
//   framesweep::expectInside    every node of the tree lies inside the frame
//   framesweep::sweep           (optionally with the ESP-NULL heuristic on) the frame cut at every length plus seeded random byte mutations (also truncated):
//                               no crash (run it under ASan) and every field offset+length inside the frame
//   framesweep::checkCorpus     optional real captures: manifest entries (IMSHARK_CORPUS_DIR, never downloaded) that
//                               name one of the protocols are decoded; skipped when absent
#include <gtest/gtest.h>

#include <cstdint>
#include <cstdlib>
#include <fstream>
#include <initializer_list>
#include <string>
#include <vector>

#include <core.h>
#include <packet/packet_info.h>
#include <packet/packet_parser.h>

#include "json_lite.h"

namespace framesweep {
    using Bytes = std::vector<uint8_t>;

    inline packet::PacketInfo parseEthernet(const Bytes &frame, uint32_t linkType = 1,
                                            dissect::ParseMode mode = dissect::ParseMode::Full, bool espNull = false) {
        packet::PacketInfo pack;
        pack.link_type = linkType;
        std::vector<char> raw(frame.begin(), frame.end());
        packet::PacketParser parser;
        parser.sessions().setEspNullHeuristic(espNull);
        parser.parsePacket(pack, raw, mode);
        return pack;
    }

    inline Bytes ethernet(uint16_t type, const Bytes &payload) {
        Bytes e = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
                   static_cast<uint8_t>(type >> 8), static_cast<uint8_t>(type & 0xff)};
        e.insert(e.end(), payload.begin(), payload.end());
        return e;
    }

    inline Bytes ipv4Packet(uint8_t protocol, const Bytes &payload, Bytes src = {10, 0, 0, 1}, Bytes dst = {10, 0, 0, 2}) {
        const uint16_t total = static_cast<uint16_t>(20 + payload.size());
        Bytes h = {0x45, 0x00, static_cast<uint8_t>(total >> 8), static_cast<uint8_t>(total & 0xff),
                   0x00, 0x01, 0x00, 0x00, 0x40, protocol, 0x00, 0x00};
        h.insert(h.end(), src.begin(), src.end());
        h.insert(h.end(), dst.begin(), dst.end());
        uint32_t sum = 0;
        for (size_t i = 0; i < 20; i += 2) sum += (h[i] << 8) | h[i + 1];
        while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
        h[10] = static_cast<uint8_t>(~sum >> 8);
        h[11] = static_cast<uint8_t>(~sum & 0xff);
        h.insert(h.end(), payload.begin(), payload.end());
        return h;
    }

    inline Bytes ipv6Packet(uint8_t nextHeader, const Bytes &payload, const Bytes &src, const Bytes &dst) {
        Bytes h = {0x60, 0, 0, 0, static_cast<uint8_t>(payload.size() >> 8), static_cast<uint8_t>(payload.size() & 0xff), nextHeader, 64};
        h.insert(h.end(), src.begin(), src.end());
        h.insert(h.end(), dst.begin(), dst.end());
        h.insert(h.end(), payload.begin(), payload.end());
        return h;
    }

    inline Bytes udpDatagram(uint16_t src, uint16_t dst, const Bytes &data) {
        const uint16_t len = static_cast<uint16_t>(8 + data.size());
        Bytes h = {static_cast<uint8_t>(src >> 8), static_cast<uint8_t>(src & 0xff), static_cast<uint8_t>(dst >> 8), static_cast<uint8_t>(dst & 0xff),
                   static_cast<uint8_t>(len >> 8), static_cast<uint8_t>(len & 0xff), 0, 0};
        h.insert(h.end(), data.begin(), data.end());
        return h;
    }

    inline bool inside(const packet::Field &f, size_t frameSize) {
        if (size_t(f.offset) + f.length > frameSize) return false;
        for (const auto &c: f.children) {
            if (!inside(c, frameSize)) return false;
        }
        return true;
    }

    inline void expectInside(const packet::PacketInfo &p, size_t frameSize, const std::string &what) {
        for (const auto &f: p.fields) EXPECT_TRUE(inside(f, frameSize)) << what << ": " << f.text;
    }

    inline void sweep(const Bytes &frame, uint32_t seed, int rounds = 400, uint32_t linkType = 1, bool espNull = false) {
        auto next = [&seed]() {
            seed = seed * 1664525u + 1013904223u;
            return seed >> 8;
        };
        for (size_t n = 0; n <= frame.size(); ++n) {
            const Bytes cut(frame.begin(), frame.begin() + n);
            expectInside(parseEthernet(cut, linkType, dissect::ParseMode::Full, espNull), n, "truncated to " + std::to_string(n));
        }
        for (int round = 0; round < rounds; ++round) {
            Bytes mutated = frame;
            const int flips = 1 + int(next() % 3);
            for (int i = 0; i < flips; ++i) mutated[next() % mutated.size()] = static_cast<uint8_t>(next());
            if (next() % 2) mutated.resize(next() % (mutated.size() + 1));
            expectInside(parseEthernet(mutated, linkType, dissect::ParseMode::Full, espNull), mutated.size(), "mutation round " + std::to_string(round));
        }
    }

    /// Optional real captures: every manifest entry whose "protocols" names one of `protocols` and whose file is in
    /// IMSHARK_CORPUS_DIR is decoded; the packets of those protocols must exist, stay inside their frames and not be
    /// malformed. Skips when the directory or such an entry is absent.
    inline void checkCorpus(std::initializer_list<const char *> protocols) {
        const char *dirEnv = std::getenv("IMSHARK_CORPUS_DIR");
        if (!dirEnv) GTEST_SKIP() << "set IMSHARK_CORPUS_DIR to a directory with the captures listed in tests/corpus/manifest.json";
        std::ifstream mf(std::string(IMSHARK_TEST_DATA_DIR) + "/../corpus/manifest.json", std::ios::binary);
        const std::string text((std::istreambuf_iterator<char>(mf)), std::istreambuf_iterator<char>());
        const auto manifest = testutil::JsonParser(text).parse();
        int checked = 0;
        for (const auto &e: manifest.at("entries").items) {
            bool names = false;
            for (const char *name: protocols) names = names || e.at("protocols").has(name);
            if (!names) continue;
            const std::string path = std::string(dirEnv) + "/" + e.str("file");
            if (!std::ifstream(path)) continue;
            core::FileProcessor fp;
            std::vector<packet::PacketInfo> packets;
            std::string message;
            const bool ng = e.str("format") == "pcapng";
            ASSERT_TRUE(ng ? fp.processPcapngFile(path, packets, message) : fp.processPcapFile(path, packets, message)) << message;
            int seen = 0;
            for (const auto &p: packets) {
                bool ours = false;
                for (const char *name: protocols) ours = ours || p.protocol == name;
                if (!ours) continue;
                ++seen;
                packet::PacketInfo details;
                ASSERT_TRUE(core::buildPacketDetails(path, p, details, &packets, &fp.captureInfo()));
                expectInside(details, details.raw_data.size(), e.str("file"));
                EXPECT_EQ(details.protocol, p.protocol);
                EXPECT_EQ(details.info, p.info);
            }
            EXPECT_GT(seen, 0) << e.str("file") << " names the protocol but no packet decoded as it";
            ++checked;
        }
        if (checked == 0) GTEST_SKIP() << "no manifest entry for these protocols is present in " << dirEnv;
    }
} // namespace framesweep
