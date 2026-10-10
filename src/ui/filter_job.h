#pragma once

#include <atomic>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#include <filter/filter.h>
#include <packet/ethernet_table.h>
#include <packet/ipsec_table.h>
#include <packet/packet_info.h>

namespace ui {
    /// One background evaluation of a display filter over a snapshot of the capture. Owned by FilterState::job; destroying
    /// it cancels and joins the thread, like the other jobs (LoadJob, SearchJob).
    ///
    /// Thread safety: the worker reads only what the job owns. `packets` is a PacketList snapshot (immutable while the job
    /// holds it: a live capture's modify() copies the list first), the MAC / IPsec tables are copies taken on the UI thread
    /// together with the snapshot, and the compiled Filter is immutable (its regexes are searched through const
    /// references). The filter evaluates packet summaries only, never the frame bytes or the details, so no dissector
    /// state is involved. The worker writes `visible` and the counters; the UI reads `visible` after `finished` is set.
    struct FilterJob {
        filter::Filter filter;
        std::string text;
        std::shared_ptr<const std::vector<packet::PacketInfo>> packets;
        double captureStartEpoch = 0;
        packet::EthernetAddressTable ethernet;
        packet::IpsecTable ipsec;
        size_t total = 0;
        std::atomic<size_t> done{0};
        std::atomic<bool> cancelRequested{false};
        std::atomic<bool> finished{false};
        bool failed = false;                // the worker ended on an exception (written before `finished`)
        std::vector<uint32_t> visible;      // result (worker, read after `finished`)
        std::vector<uint32_t> lateAmended;  // live capture: earlier rows edited while the job ran (UI thread only)
        std::thread thread;

        static constexpr size_t kSlice = 128;

        ~FilterJob() {
            cancelRequested = true;
            if (thread.joinable()) thread.join();
        }

        void run() {
            try {
                filter::Context context;
                context.captureStartEpoch = captureStartEpoch;
                context.ethernet = &ethernet;
                context.ipsec = &ipsec;
                const auto &list = *packets;
                for (size_t i = 0; i < total; ++i) {
                    // slices of kSlice rows between two looks at the cancel flag / progress counter
                    if ((i % kSlice) == 0) {
                        if (cancelRequested) break;
                        done.store(i, std::memory_order_relaxed);
                    }
                    context.previous = i ? &list[i - 1] : nullptr;
                    if (filter.matches(list[i], context)) visible.push_back(static_cast<uint32_t>(i));
                }
                if (!cancelRequested) done = total;
            } catch (...) {
                failed = true;
            }
            finished = true;
        }
    };
} // namespace ui
