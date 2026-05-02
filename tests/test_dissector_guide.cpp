// The worked example of docs/DISSECTORS.md. The guide shows this file's toy dissector step by step; because it is
// compiled and run here, the registry, Context, ByteReader and filter-field calls the guide describes cannot rot
// without a test failing. If you change an API the guide uses, change the guide and this file together.
#include <gtest/gtest.h>

#include <algorithm>

#include <core.h>
#include <dissect/reader.h>
#include <dissect/registry.h>
#include <filter/fields.h>
#include <filter/filter.h>

#include <fstream>
#include <sstream>

#include "frame_sweep.h"

using packet::Field;

namespace {
    // Toy protocol "TOY" on UDP port 40000: u16 type, u16 length, then `length` payload bytes.
    //
    // Step 1: the dissector. It never reads past `length` bytes (ByteReader fails instead), claims the packet only
    // after the header is plausible, and builds the field tree only when the mode asks for one.
    // [guide:begin dissector]
    void dissectToy(dissect::Context &ctx, const char *data, size_t length) {
        auto &pack = ctx.pack;
        pack.protocol = "TOY";

        dissect::ByteReader r(data, length);
        const uint16_t type = r.u16_be();
        const uint16_t len = r.u16_be();
        if (!r.ok()) {                           // shorter than the 4-byte header
            pack.info = "Toy [Truncated]";
            ctx.markMalformed("Toy header truncated");
            return;
        }
        pack.app_type = type;                    // a fact the filter reads: summary data, not the field tree
        pack.info = "Toy message type " + std::to_string(type);
        if (len > r.remaining()) {
            ctx.markMalformed("Toy length exceeds the datagram");
            return;
        }

        if (ctx.wantFields()) {
            const size_t o = ctx.offsetOf(data);
            Field &layer = ctx.addLayer("Toy Protocol", o, 4 + len);
            layer.add("Type: " + std::to_string(type), o, 2);
            layer.add("Length: " + std::to_string(len), o + 2, 2);
            if (len) layer.add("Payload", o + 4, len);
        }
    }
    // [guide:end]

    // Step 3: a filter field. FieldDef extractors are plain function pointers (no captures) and must be gated on the
    // protocol. Built-in protocols add their rows to the table in core/src/filter/fields.cpp instead; registerField
    // is the route for tests and plugins.
    // [guide:begin field]
    void toyType(const packet::PacketInfo &p, const filter::Context &, filter::Values &out) {
        if (p.protocol == "TOY") out.addU(p.app_type);
    }

    bool registerToyField() {
        static const bool done = filter::registerField({"toy.type", filter::FieldType::Unsigned, toyType, "Toy Protocol Message Type"});
        return done;
    }
    // [guide:end]

    // Step 2: register on a private copy of the built-in registry (the process-wide one stays untouched).
    // [guide:begin registry]
    dissect::Registry toyRegistry() {
        dissect::Registry r = dissect::Registry::builtin();
        r.registerUdpPort(40000, dissectToy);
        r.registerProtocolName("TOY", {dissectToy, nullptr, nullptr});   // Decode As: UDP only
        return r;
    }
    // [guide:end]

    framesweep::Bytes toyFrame(uint16_t port, const framesweep::Bytes &message) {
        return framesweep::ethernet(0x0800, framesweep::ipv4Packet(17, framesweep::udpDatagram(50000, port, message)));
    }

    packet::PacketInfo parseWith(const dissect::Registry &registry, const framesweep::Bytes &frame,
                                 dissect::ParseMode mode = dissect::ParseMode::Full) {
        packet::PacketInfo pack;
        pack.link_type = 1;
        std::vector<char> raw(frame.begin(), frame.end());
        packet::PacketParser parser(registry);
        parser.parsePacket(pack, raw, mode);
        return pack;
    }

    const framesweep::Bytes kMessage = {0x00, 0x07, 0x00, 0x03, 'a', 'b', 'c'};

    bool treeHas(const std::vector<Field> &fields, const std::string &text) {
        for (const auto &f: fields) {
            if (f.text == text || treeHas(f.children, text)) return true;
        }
        return false;
    }
}

TEST(DissectorGuide, RegisteredPortDecodesTheToyMessage) {
    const auto registry = toyRegistry();
    const auto frame = toyFrame(40000, kMessage);
    const auto p = parseWith(registry, frame);
    EXPECT_EQ(p.protocol, "TOY");
    EXPECT_EQ(p.info, "Toy message type 7");
    EXPECT_EQ(p.app_type, 7);
    EXPECT_TRUE(treeHas(p.fields, "Toy Protocol"));
    EXPECT_TRUE(treeHas(p.fields, "Type: 7"));
    EXPECT_TRUE(treeHas(p.fields, "Payload"));
    framesweep::expectInside(p, frame.size(), "toy message");
}

TEST(DissectorGuide, SummaryModeSkipsTheTreeButKeepsTheFacts) {
    const auto registry = toyRegistry();
    const auto p = parseWith(registry, toyFrame(40000, kMessage), dissect::ParseMode::Summary);
    EXPECT_EQ(p.protocol, "TOY");
    EXPECT_EQ(p.app_type, 7);
    EXPECT_TRUE(p.fields.empty());
}

TEST(DissectorGuide, TheBuiltInRegistryIsNotAffected) {
    const auto frame = toyFrame(40000, kMessage);
    EXPECT_EQ(parseWith(dissect::Registry::builtin(), frame).protocol, "UDP");
    EXPECT_EQ(dissect::Registry::builtin().findUdpPort(50000, 40000), nullptr);
}

TEST(DissectorGuide, DecodeAsOffersTheNameAndMovesAPort) {
    auto registry = toyRegistry();
    const auto udpNames = registry.protocolNames(false);
    const auto tcpNames = registry.protocolNames(true);
    EXPECT_NE(std::find(udpNames.begin(), udpNames.end(), "TOY"), udpNames.end());
    EXPECT_EQ(std::find(tcpNames.begin(), tcpNames.end(), "TOY"), tcpNames.end()) << "the toy handlers are UDP only";
    EXPECT_EQ(parseWith(registry, toyFrame(41000, kMessage)).protocol, "UDP");
    std::string error;
    ASSERT_TRUE(registry.decodeAs(false, 41000, "TOY", &error)) << error;
    EXPECT_EQ(parseWith(registry, toyFrame(41000, kMessage)).protocol, "TOY");
    EXPECT_FALSE(registry.decodeAs(true, 41000, "TOY", &error)) << "no TCP handler";
}

TEST(DissectorGuide, TheFilterFieldReadsTheSummary) {
    ASSERT_TRUE(registerToyField());
    const auto registry = toyRegistry();
    const auto p = parseWith(registry, toyFrame(40000, kMessage), dissect::ParseMode::Summary);
    auto match = [&](const std::string &expr, const packet::PacketInfo &pk) {
        auto r = filter::Filter::compile(expr);
        EXPECT_TRUE(r.ok) << expr << ": " << r.error.message;
        return r.ok && r.filter.matches(pk, {});
    };
    EXPECT_TRUE(match("toy.type == 7", p));
    EXPECT_FALSE(match("toy.type == 8", p));
    EXPECT_FALSE(match("toy.type == 7", parseWith(registry, toyFrame(41000, kMessage), dissect::ParseMode::Summary)))
        << "an ungated or wrongly gated field would match other packets";
}

TEST(DissectorGuide, TruncationAndMutationKeepEveryFieldInsideTheFrame) {
    const auto registry = toyRegistry();
    const auto frame = toyFrame(40000, kMessage);
    for (size_t n = 0; n <= frame.size(); ++n) {
        const framesweep::Bytes cut(frame.begin(), frame.begin() + n);
        framesweep::expectInside(parseWith(registry, cut), n, "truncated to " + std::to_string(n));
    }
    uint32_t seed = 7;
    for (int round = 0; round < 300; ++round) {
        framesweep::Bytes m = frame;
        seed = seed * 1664525u + 1013904223u;
        m[14 + 20 + 8 + (seed >> 8) % kMessage.size()] = static_cast<uint8_t>(seed >> 16);
        framesweep::expectInside(parseWith(registry, m), m.size(), "mutation " + std::to_string(round));
    }
    const auto lying = toyFrame(40000, {0x00, 0x01, 0xff, 0xff, 'x'});
    EXPECT_NE(parseWith(registry, lying).info.find("Malformed"), std::string::npos);
}

namespace {
    // The code blocks of docs/DISSECTORS.md that are marked `<!-- guide:NAME -->` must be the text between
    // `[guide:begin NAME]` and `[guide:end]` in this file, one indentation level (4 spaces) removed.
    std::string readFile(const std::string &path) {
        std::ifstream in(path, std::ios::binary);
        std::ostringstream ss;
        ss << in.rdbuf();
        return ss.str();
    }

    std::string region(const std::string &source, const std::string &name) {
        const std::string begin = "// [guide:begin " + name + "]\n";
        size_t i = source.find(begin);
        if (i == std::string::npos) return {};
        i += begin.size();
        const size_t j = source.find("    // [guide:end]", i);
        std::istringstream lines(source.substr(i, j - i));
        std::string line, out;
        while (std::getline(lines, line)) out += (line.rfind("    ", 0) == 0 ? line.substr(4) : line) + "\n";
        return out;
    }
}

TEST(DissectorGuide, TheCodeInTheGuideIsTheCodeCompiledHere) {
    const std::string doc = readFile(std::string(IMSHARK_DOCS_DIR) + "/DISSECTORS.md");
    const std::string self = readFile(IMSHARK_GUIDE_TEST_SOURCE);
    ASSERT_FALSE(doc.empty()) << "docs/DISSECTORS.md not found";
    ASSERT_FALSE(self.empty());
    for (const char *name: {"dissector", "registry", "field"}) {
        const std::string code = region(self, name);
        ASSERT_FALSE(code.empty()) << "region " << name;
        const std::string block = std::string("<!-- guide:") + name + " -->\n```cpp\n" + code + "```";
        EXPECT_NE(doc.find(block), std::string::npos)
            << "docs/DISSECTORS.md must contain, verbatim, the block for '" << name << "':\n" << block;
    }
}
