#pragma once

// Helpers shared by the fuzz harnesses (see docs/FUZZING.md). Every harness is deterministic, opens no network
// connection, keeps its memory bounded by capping the input size, and removes the temporary files it creates.

#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <string>
#include <system_error>
#include <vector>

#if defined(_WIN32)
#include <process.h>
#else
#include <unistd.h>
#endif

#include <packet/packet_info.h>

/// A broken invariant of the library is a finding just like a sanitizer report: abort so the fuzzer saves the input.
#define FUZZ_CHECK(cond)                                                                              \
    do {                                                                                              \
        if (!(cond)) {                                                                                \
            std::fprintf(stderr, "fuzz invariant violated: %s (%s:%d)\n", #cond, __FILE__, __LINE__); \
            std::abort();                                                                             \
        }                                                                                             \
    } while (0)

namespace fuzz {
    /// A path that no other process (parallel fuzzing jobs) or call of this process uses.
    inline std::string uniqueTempPath(const char *tag) {
        static std::atomic<uint64_t> sequence{0};
#if defined(_WIN32)
        const auto pid = static_cast<unsigned long>(_getpid());
#else
        const auto pid = static_cast<unsigned long>(getpid());
#endif
        return (std::filesystem::temp_directory_path() /
                ("imshark_fuzz_" + std::to_string(pid) + "_" + std::to_string(sequence.fetch_add(1)) + "_" + tag)).string();
    }

    /// A temporary file that is deleted when the object goes out of scope.
    class TempFile {
    public:
        explicit TempFile(const char *tag) : path_(uniqueTempPath(tag)) {}
        TempFile(const TempFile &) = delete;
        TempFile &operator=(const TempFile &) = delete;
        ~TempFile() {
            std::error_code ec;
            std::filesystem::remove(std::filesystem::path(path_), ec);
        }

        bool write(const uint8_t *data, size_t size) const {
            std::ofstream out(path_, std::ios::binary | std::ios::trunc);
            if (size) out.write(reinterpret_cast<const char *>(data), static_cast<std::streamsize>(size));
            return out.good();
        }
        const std::string &path() const { return path_; }

    private:
        std::string path_;
    };

    /// LINKTYPE_* values that have a link layer decoder (packet_parser.cpp and the link types of dissect/registry.cpp)
    /// plus two that have none, indexed by the first input byte of the packet harnesses.
    inline constexpr uint32_t kLinkTypes[] = {
        1,           // Ethernet
        0,           // BSD loopback (NULL)
        108,         // OpenBSD loopback
        101,         // raw IP
        12,          // raw IP (BSD)
        14,          // raw IP (OpenBSD)
        113,         // Linux cooked v1
        276,         // Linux cooked v2
        9,           // PPP
        105,         // IEEE 802.11
        127,         // 802.11 + radiotap
        192,         // PPI
        189,         // USB Linux
        220,         // USB Linux mmapped
        249,         // USBPcap
        187,         // Bluetooth HCI H4
        254,         // Bluetooth Linux monitor
        195,         // 802.15.4 with FCS
        215,         // 802.15.4 non-ASK PHY
        230,         // 802.15.4
        227,         // SocketCAN
        147,         // user DLT without a decoder
        0xFFFFFFFFu, // packet::kUndefinedLinkType
    };
    inline constexpr size_t kLinkTypeCount = sizeof(kLinkTypes) / sizeof(kLinkTypes[0]);

    inline uint32_t linkTypeFor(uint8_t selector) { return kLinkTypes[selector % kLinkTypeCount]; }

    /// Every node of the field tree lies inside a frame of `frameSize` bytes (the contract the truncation sweeps of
    /// tests/frame_sweep.h check for each dissector).
    inline bool fieldsInside(const packet::Field &f, size_t frameSize) {
        if (size_t(f.offset) + f.length > frameSize) {
            std::fprintf(stderr, "field outside the %zu byte frame: offset %u length %u: %s\n", frameSize, f.offset, f.length, f.text.c_str());
            return false;
        }
        for (const auto &child: f.children) {
            if (!fieldsInside(child, frameSize)) return false;
        }
        return true;
    }
} // namespace fuzz
