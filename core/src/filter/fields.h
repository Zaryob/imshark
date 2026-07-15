#pragma once

// The field table of the display filter: name -> type -> how to read the value(s) from a summary.

#include <array>
#include <network/address.h>
#include <initializer_list>
#include <string>
#include <string_view>
#include <vector>

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
        char text[2][18] = {};   // storage for values formatted on the fly (addMac); the views in `s` point here, so a Values must not be copied
        void addMac(const std::array<uint8_t, 6> &mac) {
            static const char digits[] = "0123456789abcdef";
            char *out = text[n];
            for (size_t i = 0; i < 6; ++i) {
                out[i * 3] = digits[mac[i] >> 4];
                out[i * 3 + 1] = digits[mac[i] & 0xF];
                out[i * 3 + 2] = i < 5 ? ':' : '\0';
            }
            v[n].s = std::string_view(out, 17);
            ++n;
        }
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

    /// Collects the field definitions of the built-in protocols while the table is built. Each protocol has a field
    /// module (core/src/dissect/<protocol>_fields.cpp, a registerXxxFields(FieldRegistry &) function) that adds the
    /// fields of that protocol; filter/field_modules.cpp lists all modules explicitly. add() refuses an incomplete
    /// definition and a name that is already taken, and remembers the problem: the table is never built from a
    /// registry that has problems (see problems()).
    class FieldRegistry {
    public:
        /// False, and nothing is added, if the name is empty or already taken or the extractor is missing.
        bool add(const FieldDef &field);
        void addAll(std::initializer_list<FieldDef> fields) { for (const auto &f: fields) add(f); }
        void addAll(const std::vector<FieldDef> &fields) { for (const auto &f: fields) add(f); }

        size_t size() const { return fields_.size(); }
        /// One line per rejected definition ("duplicate field name: tcp.port"). Empty when everything was accepted.
        const std::vector<std::string> &problems() const { return problems_; }
        /// The accepted fields, sorted by name.
        std::vector<FieldDef> sorted() const;

    private:
        std::vector<FieldDef> fields_;
        std::vector<std::string> problems_;
    };

    // Where fields live (B4): every protocol declares its filter fields next to its dissector, in a field module. The
    // modules are registered once, from the explicit list in filter/field_modules.cpp, into a FieldRegistry that becomes
    // the built-in table; after that the table is immutable. A dissector must NOT register fields from its own
    // dissection function: that made a field appear only after the first packet of its protocol and modified the table
    // while filters and worker threads were using it.
    //
    // The table is complete before any use: it is built by the first call of initFields(), findField(), allFields() or
    // builtinFields() (a function-local static, thread-safe), and the program entry points (imshark, imshark_dump) call
    // initFields() first thing. A duplicate name or an incomplete definition aborts the process with a message on stderr.
    //
    // A FieldDef pointer returned by findField() stays valid for the life of the process.

    /// Builds the built-in table now (idempotent). Nothing else is needed to make the fields available.
    void initFields();

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
