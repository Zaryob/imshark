// DNS (RFC 1035 and friends): header, flags, questions and all resource record sections with the
// common record types decoded. Also used for mDNS and for DNS over TCP.
#include "protocols.h"

#include "util.h"

#include <network/l7_application/dns_header.h>
#include <network/utils.h>

using packet::Field;

namespace {
    using namespace dissect;

    const char *typeName(uint16_t t) {
        switch (t) {
            case 1: return "A";
            case 2: return "NS";
            case 5: return "CNAME";
            case 6: return "SOA";
            case 12: return "PTR";
            case 15: return "MX";
            case 16: return "TXT";
            case 28: return "AAAA";
            case 33: return "SRV";
            case 41: return "OPT";
            case 43: return "DS";
            case 46: return "RRSIG";
            case 47: return "NSEC";
            case 48: return "DNSKEY";
            case 64: return "SVCB";
            case 65: return "HTTPS";
            case 255: return "ANY";
            default: return nullptr;
        }
    }

    std::string typeText(uint16_t t) {
        const char *n = typeName(t);
        return n ? n : "TYPE" + std::to_string(t);
    }

    std::string classText(uint16_t c) {
        switch (c & 0x7FFF) {  // the top bit is mDNS "cache flush" / "unicast response"
            case 1: return "IN";
            case 3: return "CH";
            case 4: return "HS";
            case 254: return "NONE";
            case 255: return "ANY";
            default: return "CLASS" + std::to_string(c & 0x7FFF);
        }
    }

    std::string opcodeText(unsigned op) {
        switch (op) {
            case 0: return "Standard query";
            case 1: return "Inverse query";
            case 2: return "Server status request";
            case 4: return "Notification";
            case 5: return "Update";
            default: return "Opcode " + std::to_string(op);
        }
    }

    std::string rcodeText(unsigned rc) {
        switch (rc) {
            case 0: return "No error";
            case 1: return "Format error";
            case 2: return "Server failure";
            case 3: return "No such name";
            case 4: return "Not implemented";
            case 5: return "Refused";
            default: return "Rcode " + std::to_string(rc);
        }
    }

    // Reads a (possibly compressed) name at `off`; `off` advances past it as it appears at that position.
    // Returns false on truncation, bad labels or compression loops.
    bool readName(const char *msg, size_t len, size_t &off, std::string &out) {
        out.clear();
        size_t pos = off, resume = 0;
        bool jumped = false;
        int hops = 0;
        while (true) {
            if (pos >= len) return false;
            const uint8_t l = static_cast<uint8_t>(msg[pos]);
            if (l == 0) { ++pos; break; }
            if ((l & 0xC0) == 0xC0) {
                if (pos + 1 >= len || ++hops > 16) return false;
                const size_t target = ((l & 0x3F) << 8) | static_cast<uint8_t>(msg[pos + 1]);
                if (!jumped) resume = pos + 2;
                jumped = true;
                pos = target;
                continue;
            }
            if ((l & 0xC0) != 0 || pos + 1 + l > len) return false;
            if (!out.empty()) out += '.';
            out.append(msg + pos + 1, l);
            pos += 1 + l;
            if (out.size() > 255) return false;
        }
        off = jumped ? resume : pos;
        if (out.empty()) out = "<Root>";
        return true;
    }

    struct Record {
        std::string name;
        uint16_t type = 0, cls = 0;
        uint32_t ttl = 0;
        size_t start = 0, dataOffset = 0, dataLength = 0, end = 0;
        std::string rdata;      // decoded record data for the tree ("addr 1.2.3.4" style pieces are in `treeText`)
        std::string infoText;   // what the Info column shows after the type
        std::string treeText;   // short description for the record's tree line
        bool ok = false;
    };

    std::string quoteTxt(const char *p, size_t n) {
        std::string s = "\"";
        for (size_t i = 0; i < n; ++i) s += (static_cast<unsigned char>(p[i]) >= 32 && static_cast<unsigned char>(p[i]) < 127) ? p[i] : '.';
        return s + "\"";
    }

    // decodes the type specific data of a record
    void decodeRdata(const char *msg, Record &r) {
        const char *d = msg + r.dataOffset;
        const size_t n = r.dataLength;
        size_t off = r.dataOffset;
        std::string name, name2;
        switch (r.type) {
            case 1:
                if (n == 4) { r.infoText = r.treeText = ip4(d); r.rdata = "Address: " + r.infoText; }
                break;
            case 28:
                if (n == 16) { r.infoText = r.treeText = network::formatIPv6(d); r.rdata = "AAAA Address: " + r.infoText; }
                break;
            case 2: case 5: case 12:
                if (readName(msg, r.dataOffset + n, off, name)) {
                    r.infoText = r.treeText = name;
                    r.rdata = std::string(r.type == 2 ? "Name Server: " : r.type == 5 ? "CNAME: " : "Domain Name: ") + name;
                }
                break;
            case 15:
                if (n >= 3) {
                    const unsigned pref = be16(d);
                    off += 2;
                    if (readName(msg, r.dataOffset + n, off, name)) {
                        r.infoText = std::to_string(pref) + " " + name;
                        r.treeText = "preference " + std::to_string(pref) + ", mx " + name;
                        r.rdata = "Preference: " + std::to_string(pref) + ", Mail Exchange: " + name;
                    }
                }
                break;
            case 16: { // one or more length-prefixed strings
                size_t i = 0;
                std::string all;
                while (i < n) {
                    const size_t sl = static_cast<uint8_t>(d[i]);
                    if (i + 1 + sl > n) break;
                    if (!all.empty()) all += ' ';
                    all += quoteTxt(d + i + 1, sl);
                    i += 1 + sl;
                }
                r.infoText = r.treeText = all;
                r.rdata = "TXT: " + all;
                break;
            }
            case 6:
                if (readName(msg, r.dataOffset + n, off, name) && readName(msg, r.dataOffset + n, off, name2) && off + 20 <= r.dataOffset + n) {
                    r.infoText = name + " " + name2;
                    r.treeText = "mname " + name + ", rname " + name2;
                    r.rdata = "Primary name server: " + name + ", Responsible authority: " + name2 + ", Serial: " + std::to_string(be32(msg + off)) +
                              ", Minimum TTL: " + std::to_string(be32(msg + off + 16));
                }
                break;
            case 33:
                if (n >= 7) {
                    off += 6;
                    if (readName(msg, r.dataOffset + n, off, name)) {
                        r.infoText = std::to_string(be16(d)) + " " + std::to_string(be16(d + 2)) + " " + std::to_string(be16(d + 4)) + " " + name;
                        r.treeText = "priority " + std::to_string(be16(d)) + ", weight " + std::to_string(be16(d + 2)) + ", port " + std::to_string(be16(d + 4)) + ", target " + name;
                        r.rdata = "Priority: " + std::to_string(be16(d)) + ", Weight: " + std::to_string(be16(d + 2)) + ", Port: " + std::to_string(be16(d + 4)) + ", Target: " + name;
                    }
                }
                break;
            case 41: // EDNS0 pseudo record: the class field carries the UDP payload size
                r.infoText = "<Root>";
                r.treeText = "UDP payload size " + std::to_string(r.cls);
                break;
            default:
                r.treeText = std::to_string(n) + " bytes of data";
        }
        if (r.rdata.empty()) r.rdata = "Data (" + std::to_string(n) + " bytes)";
    }

    bool parseRecord(const char *msg, size_t len, size_t &off, Record &r) {
        r.start = off;
        if (!readName(msg, len, off, r.name)) return false;
        if (len < off || len - off < 10) return false;
        r.type = be16(msg + off);
        r.cls = be16(msg + off + 2);
        r.ttl = be32(msg + off + 4);
        r.dataLength = be16(msg + off + 8);
        off += 10;
        if (len - off < r.dataLength) return false;
        r.dataOffset = off;
        off += r.dataLength;
        r.end = off;
        decodeRdata(msg, r);
        r.ok = true;
        return true;
    }

    void addFlagBits(Field &flags, uint16_t f, size_t o) {
        auto bit = [&](uint16_t mask, const char *pattern, const char *on, const char *off) {
            flags.add(std::string(pattern) + (f & mask ? on : off), o, 2);
        };
        bit(0x8000, "1... .... .... .... = Response: ", "Message is a response", "Message is a query");
        flags.add(".... " + std::string("Opcode: ") + opcodeText((f >> 11) & 0xF) + " (" + std::to_string((f >> 11) & 0xF) + ")", o, 2);
        bit(0x0400, ".... .1.. .... .... = Authoritative: ", "Server is an authority for domain", "Server is not an authority for domain");
        bit(0x0200, ".... ..1. .... .... = Truncated: ", "Message is truncated", "Message is not truncated");
        bit(0x0100, ".... ...1 .... .... = Recursion desired: ", "Do query recursively", "Do not query recursively");
        bit(0x0080, ".... .... 1... .... = Recursion available: ", "Server can do recursive queries", "Server cannot do recursive queries");
        bit(0x0020, ".... .... ..1. .... = Answer authenticated: ", "Answer/authority portion was authenticated by the server", "Answer/authority portion was not authenticated by the server");
        bit(0x0010, ".... .... ...1 .... = Non-authenticated data: ", "Acceptable", "Unacceptable");
        flags.add("Reply code: " + rcodeText(f & 0xF) + " (" + std::to_string(f & 0xF) + ")", o, 2);
    }

    void dissectMessage(Context &ctx, const char *msg, size_t len, const char *protocolName) {
        auto &pack = ctx.pack;
        pack.protocol = protocolName;

        network::DNSHeader hdr;
        if (!readStruct(msg, len, 0, hdr)) {
            ctx.markMalformed("DNS message too short");
            return;
        }
        const uint16_t id = network::ntoh16(hdr.transaction_id);
        const uint16_t flags = network::ntoh16(hdr.flags);
        const uint16_t counts[4] = {network::ntoh16(hdr.questions), network::ntoh16(hdr.answer_rrs),
                                    network::ntoh16(hdr.authority_rrs), network::ntoh16(hdr.additional_rrs)};
        const bool response = flags & 0x8000;
        const unsigned rcode = flags & 0xF;
        pack.app_flags = flags;
        pack.app_code = static_cast<uint16_t>(rcode);

        const size_t o = ctx.offsetOf(msg);
        Field *layer = nullptr;
        if (ctx.wantFields()) {
            layer = &ctx.addLayer(std::string("Domain Name System (") + (response ? "response" : "query") + ")", o, len);
            layer->add("Transaction ID: " + hexString(id, 4), o, 2);
            Field &f = layer->add("Flags: " + hexString(flags, 4) + " " + opcodeText((flags >> 11) & 0xF) + (response ? " response" : "") +
                                      ", " + rcodeText(rcode), o + 2, 2);
            addFlagBits(f, flags, o + 2);
            layer->add("Questions: " + std::to_string(counts[0]), o + 4, 2);
            layer->add("Answer RRs: " + std::to_string(counts[1]), o + 6, 2);
            layer->add("Authority RRs: " + std::to_string(counts[2]), o + 8, 2);
            layer->add("Additional RRs: " + std::to_string(counts[3]), o + 10, 2);
        }

        std::string info = opcodeText((flags >> 11) & 0xF) + (response ? " response 0x" : " 0x");
        { std::ostringstream h; h << std::hex << id; info += h.str(); }
        if (response && rcode != 0) info += " " + rcodeText(rcode);

        size_t off = sizeof(network::DNSHeader);
        bool ok = true;
        static const char *sectionNames[4] = {"Queries", "Answers", "Authoritative nameservers", "Additional records"};
        int infoRecords = 0;

        for (int section = 0; section < 4 && ok; ++section) {
            Field *sec = nullptr;
            if (layer && counts[section] > 0) {
                layer->add(sectionNames[section], o + off, 0);
                sec = &layer->children.back();
            }
            const size_t sectionStart = off;
            for (unsigned i = 0; i < counts[section] && ok; ++i) {
                if (section == 0) { // a question: name, type, class
                    const size_t start = off;
                    std::string name;
                    if (!readName(msg, len, off, name) || len < off || len - off < 4) { ok = false; break; }
                    const uint16_t t = be16(msg + off), c = be16(msg + off + 2);
                    off += 4;
                    if (i == 0) {
                        pack.app_text = name;
                        pack.app_type = t;
                    }
                    info += " " + typeText(t) + " " + name;
                    if (sec) {
                        Field &q = sec->add(name + ": type " + typeText(t) + ", class " + classText(c), o + start, off - start);
                        q.add("Name: " + name, o + start, off - start - 4);
                        q.add("Type: " + typeText(t) + " (" + std::to_string(t) + ")", o + off - 4, 2);
                        q.add("Class: " + classText(c) + " (" + hexString(c, 4) + ")", o + off - 2, 2);
                    }
                } else {
                    Record r;
                    if (!parseRecord(msg, len, off, r)) { ok = false; break; }
                    if (r.type != 41 && infoRecords < 8) { // OPT pseudo records are not interesting in the Info column
                        info += " " + typeText(r.type) + (r.infoText.empty() ? "" : " " + r.infoText);
                        ++infoRecords;
                    } else if (r.type != 41 && infoRecords == 8) {
                        info += " ...";
                        ++infoRecords;
                    }
                    if (sec) {
                        Field &rr = sec->add(r.name + ": type " + typeText(r.type) + ", class " + classText(r.cls) +
                                                 (r.treeText.empty() ? "" : ", " + r.treeText),
                                             o + r.start, r.end - r.start);
                        rr.add("Name: " + r.name, o + r.start, r.dataOffset - 10 - r.start);
                        rr.add("Type: " + typeText(r.type) + " (" + std::to_string(r.type) + ")", o + r.dataOffset - 10, 2);
                        rr.add("Class: " + classText(r.cls) + " (" + hexString(r.cls, 4) + ")", o + r.dataOffset - 8, 2);
                        rr.add("Time to live: " + std::to_string(r.ttl), o + r.dataOffset - 6, 4);
                        rr.add("Data length: " + std::to_string(r.dataLength), o + r.dataOffset - 2, 2);
                        rr.add(r.rdata, o + r.dataOffset, r.dataLength);
                    }
                }
            }
            if (sec) { sec->offset = static_cast<uint32_t>(o + sectionStart); sec->length = static_cast<uint32_t>(off - sectionStart); }
        }
        if (!ok) info += " [Malformed Packet: truncated DNS record]";
        pack.info = info;
    }
} // namespace

void dissect::dissectDns(Context &ctx, const char *data, size_t length) { dissectMessage(ctx, data, length, "DNS"); }

void dissect::dissectMdns(Context &ctx, const char *data, size_t length) { dissectMessage(ctx, data, length, "MDNS"); }

dissect::StreamFrame dissect::frameDnsTcp(const char *data, size_t length) {
    // a 2-byte length followed by a message that is at least a DNS header long and no longer than the length says
    if (length < 2) return {StreamFrame::Kind::NeedMore, 0};
    const size_t declared = be16(data);
    if (declared < sizeof(network::DNSHeader)) return {StreamFrame::Kind::Reject, 0};
    if (length < declared + 2) return {StreamFrame::Kind::NeedMore, 0};
    return {StreamFrame::Kind::Complete, declared + 2};
}

void dissect::dissectDnsTcp(Context &ctx, const char *data, size_t length) {
    // DNS over TCP: every message is preceded by its length (RFC 1035 4.2.2). Whole messages come from the
    // stream reassembly; what is present gets decoded when that did not apply (a capture that starts mid-stream).
    if (length < 2) {
        ctx.pack.protocol = "DNS";
        ctx.markMalformed("DNS over TCP: missing length field");
        return;
    }
    const size_t declared = be16(data);
    const size_t available = std::min(declared, length - 2);
    dissectMessage(ctx, data + 2, available, "DNS");
    if (available < declared) ctx.pack.info += " [message continues in later segments: " + std::to_string(available) + " of " + std::to_string(declared) + " bytes]";
}
