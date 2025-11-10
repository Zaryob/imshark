#pragma once

// Shared by the TLS tests: the fixtures of tests/data/tls (real handshakes, see tools/make_tls_fixtures.py), file and field
// helpers and a loaded capture with its session tables.
#include <gtest/gtest.h>

#include <array>
#include <cstdio>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

#include <core.h>

#include "json_lite.h"
#include "support.h"

namespace tlstest {
    using support::hex;

    inline const std::string kDir = std::string(IMSHARK_TEST_DATA_DIR) + "/tls/";

    inline std::string slurp(const std::string &path) {
        std::ifstream f(path, std::ios::binary);
        std::stringstream ss;
        ss << f.rdbuf();
        return ss.str();
    }

    inline std::vector<char> slurpBytes(const std::string &path) {
        const std::string s = slurp(path);
        return std::vector<char>(s.begin(), s.end());
    }

    inline testutil::Json expected(const std::string &name) {
        return testutil::JsonParser(slurp(kDir + "expected.json")).parse().at(name);
    }

    inline std::array<uint8_t, 32> randomOf(const std::string &hexText) {
        std::array<uint8_t, 32> r{};
        const auto bytes = hex(hexText);
        EXPECT_EQ(bytes.size(), r.size());
        for (size_t i = 0; i < r.size() && i < bytes.size(); ++i) r[i] = static_cast<uint8_t>(bytes[i]);
        return r;
    }

    inline std::string hexOfRandom(const std::array<uint8_t, 32> &r) { return support::hexOf(std::string(r.begin(), r.end())); }

    inline const packet::Field *find(const std::vector<packet::Field> &fields, const std::string &prefix) {
        for (const auto &f: fields) {
            if (f.text.rfind(prefix, 0) == 0) return &f;
            if (auto r = find(f.children, prefix)) return r;
        }
        return nullptr;
    }

    inline void collect(const std::vector<packet::Field> &fields, const std::string &prefix, std::vector<std::string> &out) {
        for (const auto &f: fields) {
            if (f.text.rfind(prefix, 0) == 0) out.push_back(f.text);
            collect(f.children, prefix, out);
        }
    }

    // every node lies inside the frame (offset + length <= size)
    inline void expectInside(const std::vector<packet::Field> &fields, size_t size) {
        for (const auto &f: fields) {
            EXPECT_LE(static_cast<size_t>(f.offset) + f.length, size) << f.text;
            expectInside(f.children, size);
        }
    }

    struct Loaded {
        std::string path, message;
        std::vector<packet::PacketInfo> packets;
        core::FileProcessor fp;
        bool ok = false;
        explicit Loaded(const std::string &file, bool pcapng = true) : path(file) {
            ok = pcapng ? fp.processPcapngFile(path, packets, message) : fp.processPcapFile(path, packets, message);
        }
        Loaded(const std::vector<char> &bytes, const std::string &name, bool pcapng = true) {
            path = support::writeTemp(name, bytes);
            ok = pcapng ? fp.processPcapngFile(path, packets, message) : fp.processPcapFile(path, packets, message);
            temp = true;
        }
        ~Loaded() { if (temp) std::remove(path.c_str()); }
        bool temp = false;

        packet::PacketInfo details(size_t i) {
            packet::PacketInfo d;
            EXPECT_TRUE(core::buildPacketDetails(path, packets[i], d, &packets, &fp.captureInfo(), nullptr, &fp.sessions()));
            return d;
        }
    };

    inline std::string raw(const std::string &hexText) { auto v = support::hex(hexText); return std::string(v.begin(), v.end()); }

} // namespace tlstest
