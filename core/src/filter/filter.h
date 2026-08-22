#pragma once

// Display filter: a small Wireshark-style expression language evaluated on packet summaries.
//
//   expr       := or
//   or         := and ( ("||" | "or") and )*
//   and        := not ( ("&&" | "and") not )*
//   not        := ("!" | "not") not | primary
//   primary    := "(" expr ")" | field [ op value | "in" "{" value... "}" ]
//   op         := == != < > <= >= eq ne lt gt le ge | contains | matches
//
// Examples:  tcp.port in {80 443} && !tcp.flags.rst     ip.addr == 10.0.0.0/8     dns or arp
//            info contains "GET"     frame.len > 1000     ipv6.src == 2001:db8::/32

#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include <packet/ethernet_table.h>
#include <packet/ipsec_table.h>
#include <packet/packet_info.h>

namespace filter {
    /// What the evaluator may need besides the packet itself.
    struct Context {
        const packet::PacketInfo *previous = nullptr; // previous captured packet (frame.time_delta)
        double captureStartEpoch = 0;                 // UTC epoch seconds of the first packet (frame.time_epoch)
        const packet::EthernetAddressTable *ethernet = nullptr; // MACs of IP frames (eth.src/eth.dst/eth.addr); without it only non-IP frames have them
        const packet::IpsecTable *ipsec = nullptr;              // SPI and sequence number of AH/ESP headers (ah.spi, ah.sequence, esp.spi, esp.sequence); without it those fields have no value
    };

    struct Error {
        std::string message;
        size_t position = 0; // byte offset in the expression text
    };

    class Filter {
    public:
        struct Node; // implementation detail

        /// Compiles `text`. An empty (or blank) expression is valid and matches every packet.
        struct Result;
        static Result compile(std::string_view text);

        bool matches(const packet::PacketInfo &packet, const Context &context = {}) const;

        /// True for the empty expression.
        bool isEmpty() const { return root_ == nullptr; }

    private:
        std::shared_ptr<const Node> root_;
    };

    struct Filter::Result {
        bool ok = false;
        Filter filter;   // valid when ok
        Error error;     // valid when !ok
    };

    struct FieldInfo {
        std::string name;
        std::string type;        // "unsigned", "boolean", "float", "string", "IPv4 address", "IPv6 address", "protocol"
        std::string description;
    };

    /// All fields and protocol names the filter knows (for help / completion), sorted by name.
    std::vector<FieldInfo> fieldInfos();
} // namespace filter
