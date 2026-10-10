#pragma once

// gzip (RFC 1952) / deflate (RFC 1951) decompression without external libraries. It streams: the input
// is read in small pieces and the output written as it is produced, so multi-gigabyte captures work.

#include <cstdint>
#include <string>

#include <load_control.h>

namespace core {
    /// True if the file starts with the gzip magic number (1f 8b).
    bool isGzipFile(const std::string &path);

    /// Hard ceiling on the output of gunzipFile when no explicit limit is given (a capture of 16 GiB is already far beyond what the
    /// viewer can index in memory, and a legitimate gzip rarely exceeds it).
    constexpr uint64_t kGunzipMaxOutput = 16ull << 30;

    /// Limits against decompression bombs. Zero `maxOutput` means "automatic": min(16 GiB, free space of the output directory - 1 GiB).
    /// The ratio check only applies once the output exceeds `ratioFloor`, so tiny, very compressible files are never refused.
    struct GunzipLimits {
        uint64_t maxOutput = 0;
        uint64_t ratioFloor = 1ull << 30;
        uint32_t maxRatio = 1000;   // output : compressed input; 0 disables the check
    };

    /// The automatic output limit for a file that would be written to `outPath`.
    uint64_t defaultGunzipMaxOutput(const std::string &outPath);

    /// Decompresses the gzip file `inPath` (any number of concatenated members) into `outPath`.
    /// Checks every member's CRC-32 and size. Returns false with `error` set on failure, and false with
    /// an empty `error` if `control` requested a cancel (the output file is then incomplete).
    /// A limit violation sets `error` and deletes the partial output file.
    /// `control->totalBytes / bytesProcessed` report the compressed bytes consumed.
    bool gunzipFile(const std::string &inPath, const std::string &outPath, std::string &error, LoadControl *control = nullptr, const GunzipLimits &limits = {});

    /// Decompresses gzip data held in memory. Fails (with `error`) on damaged data or when the output would exceed `maxOutput` bytes.
    bool gunzipMemory(const std::string &compressed, std::string &out, uint64_t maxOutput, std::string &error);

    /// Size of the decompressed data of the last successful gunzipFile call on this thread (for reporting).
    uint64_t lastGunzipOutputSize();
} // namespace core
