// bench_driver.cpp - headless load + filter benchmark for imshark_core.
//
// Built by CMake as the optional `bench_driver` target (default OFF), linked against imshark_core exactly like the
// application, so no compile line has to be kept in sync:
//   cmake -S . -B build-bench -DCMAKE_BUILD_TYPE=Release -DIMSHARK_BUILD_BENCH=ON -DIMSHARK_BUILD_TESTS=OFF
//   cmake --build build-bench --target bench_driver
//   build-bench/bench_driver capture.pcap [--filter "expression"]
// tools/benchmark.py wraps these steps and the capture generator.
//
// The load goes through FileProcessor::processFile, the call the application's loader makes (format detection, gzip,
// session tables, TCP/IP reassembly). The filter pass compiles the expression once and evaluates it for every
// packet with the previous-packet context, as the filter bar does.

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include "core.h"
#include "filter/filter.h"
#include "load_control.h"
#include "packet/packet_info.h"

#ifdef __APPLE__
#  include <mach/mach.h>
static long peak_rss_kb() {
    struct mach_task_basic_info info{};
    mach_msg_type_number_t cnt = MACH_TASK_BASIC_INFO_COUNT;
    if (task_info(mach_task_self(), MACH_TASK_BASIC_INFO, reinterpret_cast<task_info_t>(&info), &cnt) == KERN_SUCCESS)
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

static long elapsed_ms(std::chrono::steady_clock::time_point a, std::chrono::steady_clock::time_point b) {
    return static_cast<long>(std::chrono::duration_cast<std::chrono::milliseconds>(b - a).count());
}

int main(int argc, char **argv) {
    std::string path;
    std::string expression = "udp && ip.addr == 8.8.8.8";
    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "--filter") == 0 && i + 1 < argc) expression = argv[++i];
        else if (path.empty()) path = argv[i];
        else path.clear(); // more than one file name: usage error below
    }
    if (path.empty()) {
        std::fprintf(stderr, "Usage: bench_driver <capture file> [--filter \"expression\"]\n");
        return 2;
    }

    core::FileProcessor fp;
    std::vector<packet::PacketInfo> packets;
    std::string message;
    core::LoadControl ctrl;

    auto t0 = std::chrono::steady_clock::now();
    bool ok = fp.processFile(path, packets, message, &ctrl);
    auto t1 = std::chrono::steady_clock::now();
    long loadRss = peak_rss_kb();

    if (!ok) {
        std::fprintf(stderr, "Load failed: %s\n", message.c_str());
        return 1;
    }
    if (!message.empty()) std::fprintf(stderr, "Warning: %s\n", message.c_str());

    auto compiled = filter::Filter::compile(expression);
    if (!compiled.ok) {
        std::fprintf(stderr, "Filter error at %zu: %s\n", compiled.error.position, compiled.error.message.c_str());
        return 2;
    }
    filter::Context context;
    context.captureStartEpoch = fp.captureStartEpoch();
    long matched = 0;
    auto t2 = std::chrono::steady_clock::now();
    for (size_t i = 0; i < packets.size(); ++i) {
        context.previous = i ? &packets[i - 1] : nullptr;
        if (compiled.filter.matches(packets[i], context)) ++matched;
    }
    auto t3 = std::chrono::steady_clock::now();
    long filterRss = peak_rss_kb();

    std::printf("packets=%zu load_ms=%ld load_peak_rss_mb=%ld filter_ms=%ld filter_matched=%ld peak_rss_mb=%ld\n",
                packets.size(), elapsed_ms(t0, t1), loadRss > 0 ? loadRss / 1024 : -1, elapsed_ms(t2, t3), matched,
                filterRss > 0 ? filterRss / 1024 : -1);
    return 0;
}
