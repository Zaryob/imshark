#pragma once

// The field table of the display filter: name -> type -> how to read the value(s) from a summary.

#include <network/address.h>
#include <string_view>

#include <filter/filter.h>

namespace filter {
    enum class FieldType { Unsigned, Boolean, Float, String, Ipv4, Ipv6 };

    struct Value {
        uint64_t u = 0;
        double d = 0;
        std::string_view s;
        network::IpAddress a;
    };

    /// A field yields at most two values per packet (e.g. tcp.port: source and destination).
    struct Values {
        Value v[2];
        int n = 0;
        void addU(uint64_t x) { v[n].u = x; ++n; }
        void addD(double x) { v[n].d = x; ++n; }
        void addS(std::string_view x) { v[n].s = x; ++n; }
        void addA(const network::IpAddress &x) { v[n].a = x; ++n; }
    };

    using Extractor = void (*)(const packet::PacketInfo &, const Context &, Values &);

    struct FieldDef {
        const char *name;
        FieldType type;
        Extractor extract;
        const char *description;
    };

    /// nullptr if unknown. Names are matched case-insensitively (the table is lower case).
    const FieldDef *findField(std::string_view lowerName);
    const std::vector<FieldDef> &allFields();

    /// Register a custom / protocol-specific filter field dynamically.
    void registerField(FieldDef field);
} // namespace filter
