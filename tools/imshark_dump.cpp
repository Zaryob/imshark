// imshark_dump.cpp - headless "what does ImShark see" dump, the ImShark side of tools/compare_tshark.py.
//
// Loads a capture exactly as the application does (FileProcessor::processFile) and prints, for every packet, the
// protocol column and the values of the display filter fields asked for, as JSON on stdout:
//   {"packets": [{"number": 1, "protocol": "DNS", "fields": {"ip.src": ["10.0.0.1"], "udp.srcport": ["53"]}}, ...]}
// A field with no value for a packet is left out (tshark's `-T json -e` does the same). Values are text: unsigned
// numbers in decimal, IP addresses in the canonical text form, strings as they are.
//
//   imshark_dump capture.pcap [--fields name1,name2,...]
//
// Built by default (option IMSHARK_BUILD_TOOLS); the fields come from the same table as the display filter, so any
// name from docs/FILTER_FIELDS.md works. Exit codes: 0 ok, 1 load failed, 2 usage error or unknown field.

#include <cstdio>
#include <cstring>
#include <sstream>
#include <string>
#include <vector>

#include "core.h"
#include "export/export.h"
#include "filter/fields.h"
#include "load_control.h"
#include "packet/packet_info.h"

namespace {
    const char *kDefaultFields =
        "frame.number,frame.len,eth.src,eth.dst,ip.src,ip.dst,ipv6.src,ipv6.dst,ip.proto,tcp.srcport,tcp.dstport,"
        "udp.srcport,udp.dstport,dns.qry.name,dns.qry.type,http.host,http.request.method,"
        "tls.handshake.extensions_server_name,dhcp.option.hostname";

    std::string ipv4Text(const network::IpAddress &a) {
        return std::to_string(a.bytes[0]) + "." + std::to_string(a.bytes[1]) + "." + std::to_string(a.bytes[2]) + "." +
               std::to_string(a.bytes[3]);
    }

    // RFC 5952: lower case, no leading zeros, the longest run (>= 2) of zero groups becomes "::".
    std::string ipv6Text(const network::IpAddress &a) {
        unsigned g[8];
        for (int i = 0; i < 8; ++i) g[i] = (unsigned(a.bytes[2 * i]) << 8) | a.bytes[2 * i + 1];
        int bestStart = -1, bestLen = 0;
        for (int i = 0; i < 8;) {
            if (g[i] != 0) { ++i; continue; }
            int j = i;
            while (j < 8 && g[j] == 0) ++j;
            if (j - i > bestLen) { bestStart = i; bestLen = j - i; }
            i = j;
        }
        if (bestLen < 2) bestStart = -1;
        std::string out;
        char buf[8];
        for (int i = 0; i < 8; ++i) {
            if (i == bestStart) { out += "::"; i += bestLen - 1; continue; }
            if (!out.empty() && out.back() != ':') out += ':';
            std::snprintf(buf, sizeof buf, "%x", g[i]);
            out += buf;
        }
        return out;
    }

    std::vector<std::string> split(const std::string &text) {
        std::vector<std::string> out;
        std::stringstream ss(text);
        std::string item;
        while (std::getline(ss, item, ',')) if (!item.empty()) out.push_back(item);
        return out;
    }

    std::vector<std::string> valuesOf(const filter::FieldDef &def, const packet::PacketInfo &p, const filter::Context &ctx) {
        filter::Values v;
        def.extract(p, ctx, v);
        std::vector<std::string> out;
        for (int i = 0; i < v.n; ++i) {
            switch (def.type) {
                case filter::FieldType::Unsigned:
                case filter::FieldType::Boolean: out.push_back(std::to_string(v.v[i].u)); break;
                case filter::FieldType::Float: out.push_back(std::to_string(v.v[i].d)); break;
                case filter::FieldType::String: out.emplace_back(v.v[i].s); break;
                case filter::FieldType::Ipv4: out.push_back(ipv4Text(v.v[i].a)); break;
                case filter::FieldType::Ipv6: out.push_back(ipv6Text(v.v[i].a)); break;
            }
        }
        return out;
    }
} // namespace

int main(int argc, char **argv) {
    filter::initFields(); // the field table is complete before any name is looked up
    std::string path;
    std::string fieldList = kDefaultFields;
    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "--fields") == 0 && i + 1 < argc) fieldList = argv[++i];
        else if (path.empty() && argv[i][0] != '-') path = argv[i];
        else { path.clear(); break; }
    }
    if (path.empty()) {
        std::fprintf(stderr, "Usage: imshark_dump <capture file> [--fields name1,name2,...]\n");
        return 2;
    }

    std::vector<const filter::FieldDef *> defs;
    for (const auto &name: split(fieldList)) {
        const filter::FieldDef *def = filter::findField(name);
        if (!def) {
            std::fprintf(stderr, "Unknown field: %s\n", name.c_str());
            return 2;
        }
        defs.push_back(def);
    }

    core::FileProcessor fp;
    std::vector<packet::PacketInfo> packets;
    std::string message;
    core::LoadControl ctrl;
    if (!fp.processFile(path, packets, message, &ctrl)) {
        std::fprintf(stderr, "Load failed: %s\n", message.c_str());
        return 1;
    }
    if (!message.empty()) std::fprintf(stderr, "Warning: %s\n", message.c_str());

    filter::Context context;
    context.captureStartEpoch = fp.captureStartEpoch();
    std::string out = "{\"packets\": [";
    for (size_t i = 0; i < packets.size(); ++i) {
        context.previous = i ? &packets[i - 1] : nullptr;
        const auto &p = packets[i];
        out += i ? ",\n  " : "\n  ";
        out += "{\"number\": " + std::to_string(p.number) + ", \"protocol\": " + exporter::jsonString(p.protocol) +
               ", \"fields\": {";
        bool firstField = true;
        for (const auto *def: defs) {
            const auto values = valuesOf(*def, p, context);
            if (values.empty()) continue;
            out += (firstField ? "" : ", ") + exporter::jsonString(def->name) + ": [";
            for (size_t k = 0; k < values.size(); ++k) out += (k ? ", " : "") + exporter::jsonString(values[k]);
            out += "]";
            firstField = false;
        }
        out += "}}";
    }
    out += packets.empty() ? "]}\n" : "\n]}\n";
    std::fwrite(out.data(), 1, out.size(), stdout);
    return 0;
}
