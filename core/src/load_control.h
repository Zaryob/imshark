#pragma once

#include <atomic>
#include <cstdint>

namespace core {
    /// Shared between a loading thread and whoever watches it (e.g. the UI). All members are atomics, so
    /// the watcher may read them and request a cancel while the reader runs.
    struct LoadControl {
        std::atomic<bool> cancelRequested{false};
        std::atomic<uint64_t> totalBytes{0};      // size of the file being read
        std::atomic<uint64_t> bytesProcessed{0};  // bytes consumed so far
        std::atomic<uint64_t> packetsLoaded{0};
    };
} // namespace core
