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

    // Where fields live (B4): the protocols' fields are rows of the table in fields.cpp, built once on first use,
    // before any filter is compiled and before any packet is dissected. A dissector must NOT register its fields
    // lazily from its own function: that made a field appear only after the first packet of its protocol and
    // modified the table while filters and worker threads were using it.
    //
    // A FieldDef pointer returned by findField() stays valid for the life of the process.

    /// nullptr if unknown. Names are matched case-insensitively (the table is lower case).
    const FieldDef *findField(std::string_view lowerName);

    /// A snapshot of every field (built-in and registered), sorted by name.
    std::vector<FieldDef> allFields();

    /// Only the built-in table (no registerField() additions), sorted by name. This is what docs/FILTER_FIELDS.md is
    /// generated from and checked against.
    std::vector<FieldDef> builtinFields();

    /// Add a field that is not part of the built-in table (a plugin, a test). Thread-safe; the field is stored in
    /// stable storage, so earlier findField() pointers are never invalidated. `name` must point to storage that
    /// outlives the process (a string literal). Returns false, and changes nothing, if the name already exists
    /// (built-in or registered) or the definition is incomplete.
    bool registerField(FieldDef field);
} // namespace filter
