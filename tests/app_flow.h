#pragma once

// Test helpers for the enterprise/database application protocols (R2): hand-built TCP conversations written to a pcap
// file, loaded the way the application loads a capture (Summary pass), and decoded again one packet at a time (Replay).
//   appflow::bytes        hex text -> bytes as a std::string
//   appflow::Flow         a TCP conversation 10.0.0.1:clientPort <-> 10.0.0.2:serverPort; segments are PSH+ACK with exact
//                         sequence and acknowledgement numbers; load() returns the packets of the loading pass
//   appflow::details      the Replay of packet `index` (uses the frozen session tables of the loading pass)
//   appflow::expectReplayEqualsLoad   every packet's Replay shows the same protocol, Info and application facts as the loading pass
//                         asUdp() turns the conversation into UDP datagrams
//   appflow::sweepPayload one segment cut at every length and mutated at seeded random bytes, both directions: no crash under ASan,
//                         every field of every node inside its frame
#include <gtest/gtest.h>

#include <cstdio>
#include <map>
#include <string>
#include <vector>

#include <core.h>
#include <filter/filter.h>

#include "frame_sweep.h"
#include "support.h"

namespace appflow {
    inline std::string bytes(const std::string &hexText) {
        const auto v = support::hex(hexText);
        return std::string(v.begin(), v.end());
    }

    struct Segment {
        bool fromClient;
        std::string data;
        uint16_t clientPort = 0, serverPort = 0;   // the connection it belongs to
    };

    class Flow {
    public:
        Flow(uint16_t clientPort, uint16_t serverPort, std::string name) : clientPort_(clientPort), serverPort_(serverPort), name_(std::move(name)) {}

        /// The segments that follow belong to another connection (client port, server port) between the same two hosts.
        Flow &on(uint16_t clientPort, uint16_t serverPort) { clientPort_ = clientPort; serverPort_ = serverPort; return *this; }

        /// The conversation is UDP datagrams (the same addresses and ports) instead of TCP segments.
        Flow &asUdp() { udp_ = true; return *this; }
        Flow &client(const std::string &data) { segments_.push_back({true, data, clientPort_, serverPort_}); return *this; }
        Flow &server(const std::string &data) { segments_.push_back({false, data, clientPort_, serverPort_}); return *this; }

        /// The frames of the conversation (sequence/acknowledgement numbers follow the data sent so far).
        std::vector<std::vector<char>> frames() const {
            std::map<std::pair<uint16_t, uint16_t>, std::pair<uint32_t, uint32_t>> seqs;   // per connection: next client / server sequence number
            std::vector<std::vector<char>> out;
            for (const auto &s: segments_) {
                const auto hex8 = [](uint32_t v) { char b[16]; std::snprintf(b, sizeof b, "%08x", v); return std::string(b); };
                const auto hex4 = [](uint16_t v) { char b[8]; std::snprintf(b, sizeof b, "%04x", v); return std::string(b); };
                if (udp_) {
                    out.push_back(s.fromClient ? support::udpPacket("0a000001", "0a000002", hex4(s.clientPort), hex4(s.serverPort), s.data)
                                               : support::udpPacket("0a000002", "0a000001", hex4(s.serverPort), hex4(s.clientPort), s.data));
                    continue;
                }
                auto it = seqs.emplace(std::make_pair(s.clientPort, s.serverPort), std::make_pair(1000u, 5000u)).first;
                uint32_t &clientSeq = it->second.first, &serverSeq = it->second.second;
                if (s.fromClient) {
                    out.push_back(support::tcpPacket("0a000001", "0a000002", hex4(s.clientPort), hex4(s.serverPort), hex8(clientSeq), hex8(serverSeq), "18", s.data));
                    clientSeq += static_cast<uint32_t>(s.data.size());
                } else {
                    out.push_back(support::tcpPacket("0a000002", "0a000001", hex4(s.serverPort), hex4(s.clientPort), hex8(serverSeq), hex8(clientSeq), "18", s.data));
                    serverSeq += static_cast<uint32_t>(s.data.size());
                }
            }
            return out;
        }

        /// Loads the conversation like the application does; keeps the file for details().
        void load() {
            path_ = support::writeTemp(name_ + ".pcap", support::pcapBytes(frames()));
            std::string message;
            ASSERT_TRUE(fp_.processPcapFile(path_, packets_, message)) << message;
        }
        ~Flow() { if (!path_.empty()) std::remove(path_.c_str()); }

        const std::vector<packet::PacketInfo> &packets() const { return packets_; }
        core::FileProcessor &processor() { return fp_; }

        packet::PacketInfo details(size_t index) {
            packet::PacketInfo d;
            EXPECT_TRUE(core::buildPacketDetails(path_, packets_.at(index), d, &packets_, &fp_.captureInfo(), nullptr, &fp_.sessions()));
            return d;
        }

        void expectReplayEqualsLoad() {
            for (size_t i = 0; i < packets_.size(); ++i) {
                const auto &p = packets_[i];
                const auto d = details(i);
                EXPECT_EQ(d.protocol, p.protocol) << "packet " << i + 1;
                EXPECT_EQ(d.info, p.info) << "packet " << i + 1;
                EXPECT_EQ(d.app_type, p.app_type) << "packet " << i + 1;
                EXPECT_EQ(d.app_flags, p.app_flags) << "packet " << i + 1;
                EXPECT_EQ(d.app_code, p.app_code) << "packet " << i + 1;
                EXPECT_EQ(d.app_stream, p.app_stream) << "packet " << i + 1;
                EXPECT_EQ(d.app_text, p.app_text) << "packet " << i + 1;
                EXPECT_EQ(d.app_text2, p.app_text2) << "packet " << i + 1;
                EXPECT_EQ(d.tcp_pdu_start, p.tcp_pdu_start) << "packet " << i + 1;
                framesweep::expectInside(d, d.raw_data.size(), name_ + " packet " + std::to_string(i + 1));
            }
        }

    private:
        uint16_t clientPort_, serverPort_;
        std::string name_, path_;
        std::vector<Segment> segments_;
        bool udp_ = false;
        core::FileProcessor fp_;
        std::vector<packet::PacketInfo> packets_;
    };

    /// One segment cut at every length and mutated at seeded random bytes, on `port`, in both directions.
    inline void sweepPayload(const std::string &payload, uint16_t port, uint32_t seed) {
        const auto frame = [&](bool toServer, const std::string &data) {
            const auto h4 = [](uint16_t v) { char b[8]; std::snprintf(b, sizeof b, "%04x", v); return std::string(b); };
            auto f = toServer ? support::tcpPacket("0a000001", "0a000002", "c350", h4(port), "00000001", "00000001", "18", data)
                              : support::tcpPacket("0a000002", "0a000001", h4(port), "c350", "00000001", "00000001", "18", data);
            return framesweep::Bytes(f.begin(), f.end());
        };
        for (bool toServer: {true, false}) framesweep::sweep(frame(toServer, payload), seed + (toServer ? 1 : 2));
    }

    /// The same for a UDP datagram.
    inline void sweepDatagram(const std::string &payload, uint16_t port, uint32_t seed) {
        const auto frame = [&](bool toServer, const std::string &data) {
            const auto h4 = [](uint16_t v) { char b[8]; std::snprintf(b, sizeof b, "%04x", v); return std::string(b); };
            auto f = toServer ? support::udpPacket("0a000001", "0a000002", "c350", h4(port), data) : support::udpPacket("0a000002", "0a000001", h4(port), "c350", data);
            return framesweep::Bytes(f.begin(), f.end());
        };
        for (bool toServer: {true, false}) framesweep::sweep(frame(toServer, payload), seed + (toServer ? 1 : 2));
    }
} // namespace appflow
