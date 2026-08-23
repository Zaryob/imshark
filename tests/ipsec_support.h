#pragma once

// Helpers of the IPsec tests (test_ipsec.cpp, test_esp_null.cpp, test_ike*.cpp): a frame decoded the way a capture is loaded.
#include <gtest/gtest.h>

#include <functional>
#include <string>

#include <filter/filter.h>
#include <packet/packet_parser.h>
#include <stats/statistics.h>

#include "frame_sweep.h"

namespace ipsectest {
    using framesweep::Bytes;

    /// A frame decoded the way a capture is loaded: the table of AH/ESP headers is what the load pass recorded, and the filters need it.
    struct Decoded {
        packet::PacketInfo p;
        packet::IpsecTable table;
        bool matches(const std::string &expression) const {
            auto f = filter::Filter::compile(expression);
            EXPECT_TRUE(f.ok) << expression;
            filter::Context context;
            context.ipsec = &table;
            return f.ok && f.filter.matches(p, context);
        }
    };

    inline Decoded decode(const Bytes &frame, bool espNull = false, dissect::ParseMode mode = dissect::ParseMode::Full) {
        packet::PacketParser parser;
        parser.sessions().setEspNullHeuristic(espNull);
        Decoded d;
        d.p.number = 1;
        d.p.link_type = 1;
        std::vector<char> raw(frame.begin(), frame.end());
        parser.parsePacket(d.p, raw, mode);
        d.table = parser.sessions().ipsecHeaders();
        return d;
    }

    /// Some node of the field tree contains `text`.
    inline bool treeHas(const packet::PacketInfo &p, const std::string &text) {
        bool found = false;
        std::function<void(const packet::Field &)> walk = [&](const packet::Field &x) { found = found || x.text.find(text) != std::string::npos; for (const auto &c: x.children) walk(c); };
        for (const auto &x: p.fields) walk(x);
        return found;
    }

    inline const stats::HierarchyNode *hierarchyNode(const stats::HierarchyNode &n, const std::string &name) {
        if (n.name == name) return &n;
        for (const auto &c: n.children) if (const auto *f = hierarchyNode(c, name)) return f;
        return nullptr;
    }
} // namespace ipsectest
