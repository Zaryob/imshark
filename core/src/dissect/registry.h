#pragma once

#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

#include "context.h"

namespace dissect {
    /// Maps protocol identifiers to dissectors. Adding a protocol means writing a Dissector and
    /// registering it here (or on a custom registry passed to PacketParser).
    class Registry {
    public:
        void registerLinkType(uint32_t linkType, Dissector d) { linkTypes_[linkType] = std::move(d); }
        void registerEtherType(uint16_t etherType, Dissector d) { etherTypes_[etherType] = std::move(d); }
        void registerIpProtocol(uint8_t protocol, Dissector d) { ipProtocols_[protocol] = std::move(d); }
        void registerTcpPort(uint16_t port, Dissector d) { tcpPorts_[port] = std::move(d); }
        void registerUdpPort(uint16_t port, Dissector d) { udpPorts_[port] = std::move(d); }

        /// A heuristic dissector inspects a TCP payload that no port-based dissector claimed. It returns
        /// true if it recognised the payload (and then filled in the packet), false to pass.
        using Heuristic = std::function<bool(Context &ctx, const char *data, size_t length)>;
        void registerTcpHeuristic(Heuristic h) { tcpHeuristics_.push_back(std::move(h)); }
        const std::vector<Heuristic> &tcpHeuristics() const { return tcpHeuristics_; }

        /// A TCP protocol whose messages span segments (or share one). `frame` looks at the bytes of a stream (in order,
        /// starting at a message boundary) and says how long the first message is; `dissect` then decodes one complete
        /// message. Port based registration is tried before the heuristic ones; a heuristic framer answers Reject for
        /// bytes that are not its protocol.
        void registerTcpStream(uint16_t port, StreamProtocol p) { tcpStreams_[port] = std::make_shared<StreamProtocol>(std::move(p)); }
        void registerTcpStreamHeuristic(StreamProtocol p) { streamHeuristics_.push_back(std::make_shared<StreamProtocol>(std::move(p))); }
        const StreamProtocol *findTcpStream(uint16_t src, uint16_t dst) const {
            auto it = tcpStreams_.find(dst);
            if (it == tcpStreams_.end()) it = tcpStreams_.find(src);
            return it == tcpStreams_.end() ? nullptr : it->second.get();
        }
        const std::vector<std::shared_ptr<StreamProtocol>> &tcpStreamHeuristics() const { return streamHeuristics_; }
        bool hasStreamProtocols() const { return !tcpStreams_.empty() || !streamHeuristics_.empty(); }

        const Dissector *findLinkType(uint32_t linkType) const { return find(linkTypes_, linkType); }
        const Dissector *findEtherType(uint16_t etherType) const { return find(etherTypes_, etherType); }
        const Dissector *findIpProtocol(uint8_t protocol) const { return find(ipProtocols_, protocol); }

        /// Application protocol for a TCP/UDP segment: the destination port wins over the source port.
        const Dissector *findTcpPort(uint16_t src, uint16_t dst) const { return findPort(tcpPorts_, src, dst); }
        const Dissector *findUdpPort(uint16_t src, uint16_t dst) const { return findPort(udpPorts_, src, dst); }

        /// A UDP heuristic works like the TCP one: it inspects a datagram no port claimed and must validate the message
        /// structure before it claims it (a wrong claim hides what the datagram really is).
        void registerUdpHeuristic(Heuristic h) { udpHeuristics_.push_back(std::move(h)); }
        const std::vector<Heuristic> &udpHeuristics() const { return udpHeuristics_; }

        // ---- Decode As: choose the application protocol of a port by name --------------------------------------------
        /// What a protocol offers to Decode As: a UDP dissector and/or a TCP one (a stream protocol is preferred for TCP).
        struct Handlers {
            Dissector udp;
            Dissector tcp;
            std::shared_ptr<StreamProtocol> stream;
        };
        void registerProtocolName(const std::string &name, Handlers h) { named_[name] = std::move(h); }
        /// Names usable for the transport, sorted.
        std::vector<std::string> protocolNames(bool tcp) const;
        /// Makes `port` carry `protocol` (replacing whatever was registered for it). False if the protocol does not
        /// exist for that transport; `error` then says why.
        bool decodeAs(bool tcp, uint16_t port, const std::string &protocol, std::string *error = nullptr);

        /// Registry with all built-in dissectors.
        static const Registry &builtin();

    private:
        template<typename Map, typename Key>
        static const Dissector *find(const Map &map, Key key) {
            auto it = map.find(key);
            return it == map.end() ? nullptr : &it->second;
        }

        template<typename Map>
        static const Dissector *findPort(const Map &map, uint16_t src, uint16_t dst) {
            if (auto d = find(map, dst)) return d;
            return find(map, src);
        }

        std::unordered_map<uint32_t, Dissector> linkTypes_;
        std::unordered_map<uint16_t, Dissector> etherTypes_;
        std::unordered_map<uint8_t, Dissector> ipProtocols_;
        std::unordered_map<uint16_t, Dissector> tcpPorts_;
        std::unordered_map<uint16_t, Dissector> udpPorts_;
        std::vector<Heuristic> tcpHeuristics_;
        std::vector<Heuristic> udpHeuristics_;
        std::map<std::string, Handlers> named_;
        std::unordered_map<uint16_t, std::shared_ptr<StreamProtocol>> tcpStreams_;
        std::vector<std::shared_ptr<StreamProtocol>> streamHeuristics_;
    };
} // namespace dissect
