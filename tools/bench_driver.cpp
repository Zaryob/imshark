// bench_driver.cpp — headless load benchmark for imshark_core
// Compile: see tools/benchmark.py or run directly:
//   c++ -std=c++20 -O2 -Icore/src bench_driver.cpp build-bench/core/libimshark_core.a \
//       -framework CoreFoundation -o bench_driver   # macOS
//   ./bench_driver tests/data/bench_500k.pcap

#include <chrono>
#include <cstdio>
#include <string>
#include <vector>

#include "core.h"
#include "packet/packet_info.h"
#include "load_control.h"

// ── Peak RSS ──────────────────────────────────────────────────────────────────
#ifdef __APPLE__
#  include <mach/mach.h>
static long peak_rss_kb() {
    struct mach_task_basic_info info{};
    mach_msg_type_number_t cnt = MACH_TASK_BASIC_INFO_COUNT;
    if (task_info(mach_task_self(), MACH_TASK_BASIC_INFO,
                  reinterpret_cast<task_info_t>(&info), &cnt) == KERN_SUCCESS)
        return static_cast<long>(info.resident_size_max / 1024);
    return -1;
}
#elif defined(__linux__)
#  include <sys/resource.h>
static long peak_rss_kb() {
    struct rusage ru{};
    getrusage(RUSAGE_SELF, &ru);
    return ru.ru_maxrss; // kB on Linux
}
#else
static long peak_rss_kb() { return -1; }
#endif

int main(int argc, char **argv) {
    if (argc < 2) {
        std::fprintf(stderr, "Usage: bench_driver <file.pcap|file.pcapng>\n");
        return 1;
    }
    std::string path = argv[1];

    core::FileProcessor fp;
    std::vector<packet::PacketInfo> packets;
    std::string message;
    core::LoadControl ctrl;

    auto t0 = std::chrono::steady_clock::now();

    bool ok;
    // Detect format by extension / magic
    if (path.size() >= 4 &&
        (path.substr(path.size() - 4) == ".pcap" ||
         path.substr(path.size() - 7) == ".pcap.gz")) {
        ok = fp.processPcapFile(path, packets, message, &ctrl);
    } else {
        // Try pcapng, fall back to pcap
        ok = fp.processPcapngFile(path, packets, message, &ctrl);
        if (!ok) {
            message.clear();
            ok = fp.processPcapFile(path, packets, message, &ctrl);
        }
    }

    auto t1 = std::chrono::steady_clock::now();
    long rss_kb = peak_rss_kb();
    long ms = std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count();

    if (!ok) {
        std::fprintf(stderr, "Load failed: %s\n", message.c_str());
        return 1;
    }
    if (!message.empty()) {
        std::fprintf(stderr, "Warning: %s\n", message.c_str());
    }

    long n = static_cast<long>(packets.size());
    long rss_mb = rss_kb > 0 ? rss_kb / 1024 : -1;
    std::printf("packets=%ld load_ms=%ld peak_rss_mb=%ld\n", n, ms, rss_mb);
    return 0;
}
