#pragma once

#include <atomic>
#include <cstdint>
#include <fstream>
#include <functional>
#include <string>
#include <vector>

#include <packet/packet_info.h>
#include <network/ip_reassembly.h>

namespace core {
    /// Random access to the frames of an already loaded capture. Keeps the file open, so reading many
    /// packets is cheap (unlike readPacketBytes(), which reopens the file every time).
    class CaptureReader {
    public:
        explicit CaptureReader(const std::string &filepath);

        bool isOpen() const { return file_.is_open(); }

        /// Reads the captured frame of `summary`. Returns false on I/O errors (file moved or truncated).
        bool read(const packet::PacketInfo &summary, std::vector<char> &out);

    private:
        std::ifstream file_;
    };

    /// Progress / cancellation of a scan (shared with the thread that runs it).
    struct ScanControl {
        std::atomic<bool> cancelRequested{false};
        std::atomic<uint64_t> total{0};   // number of frames that will be visited
        std::atomic<uint64_t> done{0};    // frames visited so far
    };

    /// Visits the frames of `order` (indices into `packets`) one after the other, in that order, and
    /// calls `visit(summary, frame)` for each. `visit` returns false to stop early. Packets whose frame
    /// cannot be read are skipped. Returns false if the scan was cancelled or the file could not be opened;
    /// true if it ran to the end or was stopped by `visit`.
    bool scanPackets(const std::string &filepath, const std::vector<packet::PacketInfo> &packets,
                     const std::vector<uint32_t> &order,
                     const std::function<bool(const packet::PacketInfo &, const std::vector<char> &)> &visit,
                     ScanControl *control = nullptr);

    /// Rebuilds the whole IP payload of a reassembled datagram. `completing` is the packet that finished it
    /// (ip_frag == 2); the earlier fragments are the packets annotated with `reassembled_in == completing.number`.
    /// Their frames are read through `reader`. Optionally reports the numbers of all fragments and the upper layer
    /// protocol announced by the first one. Returns false if a frame cannot be read or the datagram is not complete.
    bool reassembleIpPayload(CaptureReader &reader, const std::vector<packet::PacketInfo> &packets,
                             const packet::PacketInfo &completing, std::vector<char> &payload,
                             std::vector<uint32_t> *fragmentNumbers = nullptr, uint8_t *protocol = nullptr);

    /// Rebuilds the message a packet completed (`completing.tcp_pdu_state == 2`): the bytes of its direction of the
    /// connection in [tcp_pdu_start, tcp_pdu_start + tcp_pdu_len), taken from the packets of that direction in capture
    /// order (segments that were themselves reassembled from IP fragments are handled). `numbers` receives the packets
    /// that contributed bytes. Returns false if a byte is missing or a frame cannot be read.
    bool reassembleTcpPdu(CaptureReader &reader, const std::vector<packet::PacketInfo> &packets, const packet::PacketInfo &completing,
                          std::string &pdu, std::vector<uint32_t> &numbers);
} // namespace core
