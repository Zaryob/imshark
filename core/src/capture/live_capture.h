#pragma once

// Live capture: the UI independent core. A background thread reads packets from a libpcap interface and
// appends every one of them to a temporary classic pcap file, so the file offset based summary / detail
// model works unchanged for a capture that is still running. The packets that arrived since the last poll
// are handed to the consumer as small records (offset, length, timestamp, link type); appendCapturedPackets()
// turns them into summaries through the same per-packet path the file loaders use.
//
// Threading: LiveCapture may be driven from one thread (the UI) while its own capture thread runs: start(),
// stop(), the state getters and takePackets() are safe to call every frame. appendCapturedPackets() belongs
// to the consumer thread (it mutates the packet list).
//
// Without libpcap (IMSHARK_LIVE_CAPTURE=OFF or the library was not found) liveCaptureAvailable() is false,
// listInterfaces()/validateCaptureFilter()/LiveCapture::start() fail with kNotAvailable, and everything else
// (the temp file writer, the packet queue, the consumer) still works - IMSHARK_HAVE_LIVE_CAPTURE is defined
// when the real implementation is built.

#include <atomic>
#include <cstdint>
#include <fstream>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include <core.h>
#include <packet/packet_info.h>

struct pcap;   // libpcap's pcap_t, kept opaque so this header does not need pcap.h

namespace capture {
    /// The error text of every function when live capture is compiled out.
    inline const char *const kNotAvailable = "Live capture is not available in this build";

    /// Text of the permission error (the OS error text of libpcap is appended to it).
    inline const char *const kPermissionDenied =
        "Permission denied: capturing needs access to /dev/bpf* (macOS) or CAP_NET_RAW (Linux)";

    /// true if this build can capture (IMSHARK_HAVE_LIVE_CAPTURE).
    bool liveCaptureAvailable();

    struct InterfaceDesc {
        std::string name;          // what start() takes ("en0", "eth0", "\Device\NPF_{...}")
        std::string description;   // human readable text from the OS (may be empty)
        std::string addresses;     // IPv4 / IPv6 addresses, comma separated
        bool loopback = false;
        bool up = false;
        bool running = false;
        bool wireless = false;
    };

    struct InterfaceList {
        std::vector<InterfaceDesc> interfaces;
        std::string error;         // empty on success
    };

    /// Enumerates the capture interfaces. Needs no privileges.
    InterfaceList listInterfaces();

    struct FilterCheck {
        bool ok = false;
        std::string error;         // compiler message (or kNotAvailable) when !ok
    };

    /// Compiles the BPF capture filter `expr` for `linkType` (a LINKTYPE_ / DLT value; 1 = Ethernet) and `snaplen`
    /// without opening any device (pcap_open_dead + pcap_compile), so it needs no privileges. An empty expression is valid.
    FilterCheck validateCaptureFilter(const std::string &expr, uint32_t linkType = 1, uint32_t snaplen = 262144);

    struct CaptureOptions {
        std::string interfaceName;
        std::string filter;                // BPF capture filter, may be empty
        uint32_t snaplen = 262144;
        bool promiscuous = true;
    };

    /// One captured packet that is in the temp file but has not been summarised yet.
    struct CapturedPacket {
        uint64_t fileOffset = 0;      // of the frame bytes in the temp file (what PacketInfo::file_offset holds)
        uint32_t capturedLength = 0;
        uint32_t originalLength = 0;
        uint64_t tsSeconds = 0;       // capture time (seconds since the epoch)
        uint32_t tsMicros = 0;
        uint32_t linkType = 1;
    };

    class LiveCapture {
    public:
        LiveCapture();
        ~LiveCapture();                // stops the capture; removes the temp file unless it was released
        LiveCapture(const LiveCapture &) = delete;
        LiveCapture &operator=(const LiveCapture &) = delete;

        /// Opens the interface (pcap_create / pcap_activate), applies the filter, creates the temp file and starts the
        /// capture thread. Returns false and sets lastError() on failure (nothing keeps running then). A capture that
        /// is still running is stopped first; the temp file of an earlier capture that was not released is removed.
        bool start(const CaptureOptions &options);

        /// Stops the capture thread and flushes the file. Idempotent; the packets stay available through
        /// takePackets() and the temp file stays on disk.
        void stop();

        /// true while the capture records packets; turns false after stop(), when the capture thread ended on its
        /// own (device error) and when a write to the temp file failed (lastError() then says why).
        bool running() const { return running_; }
        uint64_t packetCount() const { return packetCount_; }     // packets written to the temp file
        uint64_t droppedCount() const { return dropped_; }        // pcap_stats ps_drop (kernel buffer overruns)
        uint32_t linkType() const { return linkType_; }           // LINKTYPE of the temp file (valid after start())
        uint32_t snaplen() const { return snaplen_; }
        std::string lastError() const;                            // empty if none; also set when the thread dies
        std::string tempPath() const;                             // classic pcap file in the system temp dir

        /// Moves the packets that arrived since the last call into `out` (appended, in capture order) and returns
        /// how many; `maxCount` (0 = all) bounds the batch, the rest stays queued for the next call. Their bytes
        /// are already flushed to the temp file. start() drops what was not taken, so poll until this returns 0
        /// after stop() before starting again.
        size_t takePackets(std::vector<CapturedPacket> &out, size_t maxCount = 0);

        /// The file now belongs to the caller (e.g. the UI keeps it as the open capture); the destructor and the next
        /// start() leave it alone. Returns its path.
        std::string releaseTempFile();

        // ---- internal seam (also used by the tests): everything but the pcap device -----------------------------
        /// Creates the temp file and the packet queue like start() does, without opening a device or starting a
        /// thread. packets are then fed with injectPacket(); stop() ends the session. Works in every build.
        bool beginInjected(uint32_t linkType, uint32_t snaplen);
        /// Writes one packet to the temp file, flushes and queues it - the exact path of the capture thread.
        /// Frames longer than the snaplen are truncated (originalLength keeps the wire length).
        bool injectPacket(uint64_t tsSeconds, uint32_t tsMicros, const std::vector<char> &frame, uint32_t originalLength = 0);

    private:
        // The libpcap specific part (live_capture_pcap.cpp, or live_capture_stub.cpp without libpcap).
        bool openDevice(const CaptureOptions &options, uint32_t &linkType, std::string &error);
        void breakCapture();           // pcap_breakloop
        void closeDevice();
        void captureLoop();            // runs on thread_ until stopRequested_ or an error

        bool openFile(uint32_t linkType, uint32_t snaplen);
        bool writeRecord(uint64_t tsSeconds, uint32_t tsMicros, const char *data, uint32_t capturedLength, uint32_t originalLength);
        void publish();                // flush the file, then make the pending records visible to takePackets()
        void setError(const std::string &text);
        void failWrite(const std::string &text);   // error + end of the capture after a failed file write
        void removeTemp();
        void resetSession();
        friend size_t appendCapturedPackets(LiveCapture &, core::FileProcessor &, std::vector<packet::PacketInfo> &, size_t,
                                            std::vector<uint32_t> *);

        mutable std::mutex mutex_;     // guards queue_, error_, path_
        std::vector<CapturedPacket> queue_;
        std::string error_, path_;

        std::mutex writerMutex_;       // serialises writeRecord/publish (capture thread vs. injected packets)
        std::ofstream file_;
        uint64_t fileSize_ = 0;
        std::vector<CapturedPacket> pending_;

        std::atomic<bool> running_{false};
        std::atomic<bool> stopRequested_{false};
        std::atomic<bool> writeFailed_{false};
        std::atomic<uint64_t> packetCount_{0};
        std::atomic<uint64_t> dropped_{0};
        std::atomic<uint32_t> linkType_{1};
        uint32_t snaplen_ = 262144;
        bool released_ = false;
        std::thread thread_;
        ::pcap *device_ = nullptr;
    };

    /// Consumer side: dissects the packets that arrived since the last call and appends their summaries to
    /// `packets`, through core::FileProcessor::appendLivePacket - the same path as loading the temp file later,
    /// so live packets look identical to a file opened afterwards. The frame bytes are read back from the temp
    /// file. `processor` must be fresh for this capture (a new FileProcessor; the first call runs beginLive()).
    /// Returns the number of packets appended. Call it from one thread, e.g. once per UI frame. `maxPackets` (0 = all)
    /// bounds the work of one call (the rest stays queued); `amended` (optional) receives the indices of earlier
    /// summaries that were edited in place (see FileProcessor::appendLivePacket).
    size_t appendCapturedPackets(LiveCapture &live, core::FileProcessor &processor, std::vector<packet::PacketInfo> &packets,
                                 size_t maxPackets = 0, std::vector<uint32_t> *amended = nullptr);
} // namespace capture
