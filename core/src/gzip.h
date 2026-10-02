#pragma once

// gzip (RFC 1952) / deflate (RFC 1951) decompression without external libraries. It streams: the input
// is read in small pieces and the output written as it is produced, so multi-gigabyte captures work.

#include <string>

#include <load_control.h>

namespace core {
    /// True if the file starts with the gzip magic number (1f 8b).
    bool isGzipFile(const std::string &path);

    /// Decompresses the gzip file `inPath` (any number of concatenated members) into `outPath`.
    /// Checks every member's CRC-32 and size. Returns false with `error` set on failure, and false with
    /// an empty `error` if `control` requested a cancel (the output file is then incomplete).
    /// `control->totalBytes / bytesProcessed` report the compressed bytes consumed.
    bool gunzipFile(const std::string &inPath, const std::string &outPath, std::string &error, LoadControl *control = nullptr);

    /// Decompresses gzip data held in memory. Fails (with `error`) on damaged data or when the output would exceed `maxOutput` bytes.
    bool gunzipMemory(const std::string &compressed, std::string &out, uint64_t maxOutput, std::string &error);

    /// Size of the decompressed data of the last successful gunzipFile call on this thread (for reporting).
    uint64_t lastGunzipOutputSize();
} // namespace core
