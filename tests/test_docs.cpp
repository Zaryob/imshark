// Keeps the user documentation from rotting: what docs/ says about filter fields, link types and Decode As names is
// compared with the code. A failure names the missing item. docs/FILTER_FIELDS.md is generated: run the tests with
// IMSHARK_UPDATE_DOCS=1 to rewrite it from the field table.
#include <gtest/gtest.h>

#include <algorithm>
#include <cstdlib>
#include <fstream>
#include <set>
#include <sstream>

#include <core.h>
#include <dissect/registry.h>
#include <filter/fields.h>
#include <filter/filter.h>
#include <packet/packet_parser.h>

namespace {
    std::string readFile(const std::string &path) {
        std::ifstream in(path, std::ios::binary);
        std::ostringstream ss;
        ss << in.rdbuf();
        return ss.str();
    }

    std::string docPath(const char *name) { return std::string(IMSHARK_DOCS_DIR) + "/" + name; }

    // The generated reference: one row per built-in field, in table (name) order.
    std::string filterReference() {
        std::set<std::string> builtin;
        for (const auto &f: filter::builtinFields()) builtin.insert(f.name);
        std::ostringstream out;
        out << "# Display Filter Field Reference\n\n"
               "<!-- Generated from core/src/filter/fields.cpp by the test Docs.FilterReferenceIsGeneratedFromTheFieldTable.\n"
               "     Do not edit by hand: run the tests with IMSHARK_UPDATE_DOCS=1 to rewrite it. -->\n\n"
               "Every field the display filter knows (the same list as the `?` button next to the filter bar). A field of type\n"
               "`protocol` is true when the packet contains the protocol; the other types are compared with the operators described\n"
               "in the [User Guide](USER_GUIDE.md#display-filters). Names are lower case.\n\n"
               "| Field | Type | Description |\n|---|---|---|\n";
        size_t count = 0;
        for (const auto &f: filter::fieldInfos()) {
            if (!builtin.count(f.name)) continue;
            std::string description = f.description;
            for (size_t p = 0; (p = description.find('|', p)) != std::string::npos; p += 2) description.replace(p, 1, "\\|");
            out << "| `" << f.name << "` | " << f.type << " | " << description << " |\n";
            ++count;
        }
        out << "\n" << count << " fields.\n";
        return out.str();
    }
}

TEST(Docs, FilterReferenceIsGeneratedFromTheFieldTable) {
    const std::string expected = filterReference();
    const std::string path = docPath("FILTER_FIELDS.md");
    if (const char *update = std::getenv("IMSHARK_UPDATE_DOCS"); update && *update && std::string(update) != "0") {
        std::ofstream(path, std::ios::binary) << expected;
    }
    const std::string actual = readFile(path);
    ASSERT_FALSE(actual.empty()) << path << " is missing; run the tests with IMSHARK_UPDATE_DOCS=1";
    if (actual != expected) {
        // name the first field that differs so the failure is actionable
        std::istringstream a(actual), e(expected);
        std::string la, le;
        size_t line = 0;
        while (true) {
            const bool ga = static_cast<bool>(std::getline(a, la)), ge = static_cast<bool>(std::getline(e, le));
            ++line;
            if (!ga && !ge) break;
            if (!ga || !ge || la != le) {
                ADD_FAILURE() << "docs/FILTER_FIELDS.md differs from the field table at line " << line << "\n  doc : " << (ga ? la : "(end)")
                              << "\n  code: " << (ge ? le : "(end)") << "\nRegenerate with IMSHARK_UPDATE_DOCS=1";
                break;
            }
        }
    }
}

TEST(Docs, EveryFieldIsInTheReferenceAndTheReferenceIsLinked) {
    const std::string reference = readFile(docPath("FILTER_FIELDS.md"));
    for (const auto &f: filter::builtinFields()) {
        EXPECT_NE(reference.find(std::string("| `") + f.name + "` |"), std::string::npos) << "filter field missing from docs/FILTER_FIELDS.md: " << f.name;
    }
    const std::string guide = readFile(docPath("USER_GUIDE.md"));
    ASSERT_FALSE(guide.empty()) << "docs/USER_GUIDE.md is missing";
    EXPECT_NE(guide.find("FILTER_FIELDS.md"), std::string::npos) << "the user guide must link the generated field reference";
}

TEST(Docs, SupportMatrixNamesEveryLinkTypeTheParserHandles) {
    const std::string matrix = readFile(docPath("SUPPORT_MATRIX.md"));
    ASSERT_FALSE(matrix.empty());
    packet::PacketParser parser;
    int found = 0;
    for (uint32_t linkType = 0; linkType < 400; ++linkType) {
        packet::PacketInfo pack;
        pack.link_type = linkType;
        std::vector<char> raw(96, 0);
        parser.parsePacket(pack, raw, dissect::ParseMode::Summary);
        if (pack.info.rfind("Unsupported link type", 0) == 0) continue;
        ++found;
        // a link type id appears as a table cell: "| 105 |", "| 12, 14, 101 |" ...
        bool listed = false;
        std::istringstream lines(matrix);
        std::string line;
        while (std::getline(lines, line)) {
            if (line.rfind("| ", 0) != 0) continue;
            const size_t end = line.find(" |", 2);
            if (end == std::string::npos) continue;
            std::istringstream ids(line.substr(2, end - 2));
            std::string id;
            while (std::getline(ids, id, ',')) {
                if (id.find_first_not_of(" 0123456789") == std::string::npos && std::atoi(id.c_str()) == static_cast<int>(linkType) && id.find_first_of("0123456789") != std::string::npos) listed = true;
            }
        }
        EXPECT_TRUE(listed) << "link type " << linkType << " is decoded but not in the docs/SUPPORT_MATRIX.md link type table";
    }
    EXPECT_GE(found, 15);
}

TEST(Docs, SupportMatrixAndUserGuideNameEveryDecodeAsProtocol) {
    const std::string matrix = readFile(docPath("SUPPORT_MATRIX.md"));
    const std::string guide = readFile(docPath("USER_GUIDE.md"));
    ASSERT_FALSE(matrix.empty());
    ASSERT_FALSE(guide.empty());
    std::set<std::string> names;
    for (bool tcp: {false, true}) {
        for (const auto &n: dissect::Registry::builtin().protocolNames(tcp)) names.insert(n);
    }
    ASSERT_FALSE(names.empty());
    for (const auto &n: names) {
        EXPECT_NE(matrix.find("`" + n + "`"), std::string::npos) << "Decode As protocol missing from the SUPPORT_MATRIX Decode As list: " << n;
        EXPECT_NE(guide.find("`" + n + "`"), std::string::npos) << "Decode As protocol missing from the USER_GUIDE Decode As list: " << n;
    }
}
