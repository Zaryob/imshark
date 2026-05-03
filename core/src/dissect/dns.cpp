#include "protocols.h"

#include "util.h"

#include <network/l7_application/dns_header.h>
#include <network/utils.h>

using packet::Field;

namespace {
    using namespace dissect;

    bool parseQuestion(const char *data, size_t &offset, size_t length, std::ostringstream &oss) {
        std::string domainName = network::getDomainName(data, offset, length);
        if (length < offset || length - offset < 4) return false;
        const uint16_t qType = be16(data + offset);
        offset += 4; // type + class

        const std::string qTypeStr = (qType == 1) ? "A" : (qType == 28) ? "AAAA" : std::to_string(qType);
        oss << " " << qTypeStr << " " << domainName;
        return true;
    }

    bool parseAnswer(const char *data, size_t &offset, size_t length, std::ostringstream &oss) {
        std::string domainName = network::getDomainName(data, offset, length);
        if (length < offset || length - offset < 10) return false;

        const uint16_t type = be16(data + offset);
        const uint16_t dataLength = be16(data + offset + 8);
        offset += 10; // type, class, ttl, rdlength

        if (length - offset < dataLength) return false;

        oss << " " << domainName;

        if (type == 1 && dataLength == 4) { // A record (IPv4)
            oss << " A " << ip4(data + offset);
        } else if (type == 28 && dataLength == 16) { // AAAA record (IPv6)
            oss << " AAAA " << network::formatIPv6(data + offset);
        } else if (type == 6) { // SOA record
            oss << " SOA";
        }

        offset += dataLength;
        return true;
    }
} // namespace

void dissect::dissectDns(Context &ctx, const char *data, size_t length) {
    auto &pack = ctx.pack;
    pack.protocol = "DNS";

    network::DNSHeader dnsHeader;
    if (!readStruct(data, length, 0, dnsHeader)) {
        ctx.markMalformed("DNS message too short");
        return;
    }

    const uint16_t transactionID = network::ntoh16(dnsHeader.transaction_id);
    const uint16_t flags = network::ntoh16(dnsHeader.flags);
    const uint16_t questions = network::ntoh16(dnsHeader.questions);
    const uint16_t answerRRs = network::ntoh16(dnsHeader.answer_rrs);

    if (ctx.wantFields()) {
        const size_t o = ctx.offsetOf(data);
        Field &l = ctx.addLayer(std::string("Domain Name System (") + ((flags & 0x8000) ? "response" : "query") + ")", o, length);
        l.add("Transaction ID: " + hexString(transactionID, 4), o, 2);
        l.add("Flags: " + hexString(flags, 4), o + 2, 2);
        l.add("Questions: " + std::to_string(questions), o + 4, 2);
        l.add("Answer RRs: " + std::to_string(answerRRs), o + 6, 2);
        l.add("Authority RRs: " + std::to_string(network::ntoh16(dnsHeader.authority_rrs)), o + 8, 2);
        l.add("Additional RRs: " + std::to_string(network::ntoh16(dnsHeader.additional_rrs)), o + 10, 2);
        if (length > sizeof(network::DNSHeader)) {
            l.add("Records (" + std::to_string(length - sizeof(network::DNSHeader)) + " bytes)", o + sizeof(network::DNSHeader),
                  length - sizeof(network::DNSHeader));
        }
    }

    std::ostringstream oss;
    oss << ((flags & 0x8000) ? "Standard query response 0x" : "Standard query 0x") << std::hex << transactionID << std::dec;

    size_t offset = sizeof(network::DNSHeader);
    bool ok = true;
    for (int i = 0; ok && i < questions; ++i) ok = parseQuestion(data, offset, length, oss);
    for (int i = 0; ok && i < answerRRs; ++i) ok = parseAnswer(data, offset, length, oss);
    if (!ok) oss << " [Malformed Packet: truncated DNS record]";

    pack.info = oss.str();
}
