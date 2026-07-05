#pragma once

// Registry of the capture file formats ImShark knows (ROADMAP B5): each entry has a magic number probe, a display
// name and, for formats that can be read, the factory of its CaptureFileReader. Formats that are only recognised
// (named in the "unsupported" diagnostic) have no factory. Probing goes through the entries in table order, so the
// strict magic numbers come first and the heuristic ones (Endace ERF has no magic at all) last.

#include <cstddef>
#include <cstdint>
#include <memory>
#include <vector>

#include <core.h>
#include <io/capture_file.h>

namespace core::io {
    /// Number of leading bytes the probes may look at.
    constexpr size_t kProbeBytes = 24;

    struct FormatDescriptor {
        FileFormat format;
        const char *name;
        bool (*matches)(const uint8_t *buf, size_t len);   // len <= kProbeBytes: the first bytes of the file
        ReaderFactory makeReader;                           // nullptr: recognised but not readable (yet)
        bool container;                                     // a wrapper around a capture file (gzip): unpacked first, then the format inside is detected
    };

    /// All known formats, in probing order.
    const std::vector<FormatDescriptor> &captureFormats();

    /// The descriptor of `format`, nullptr for Unknown.
    const FormatDescriptor *findFormat(FileFormat format);

    /// The first format whose probe accepts the leading bytes, Unknown if none.
    FileFormat identifyFormat(const uint8_t *buf, size_t len);

    /// The built-in readers (also reachable through the registry).
    std::unique_ptr<CaptureFileReader> makePcapReader();
    std::unique_ptr<CaptureFileReader> makePcapngReader();
    std::unique_ptr<CaptureFileReader> makeSnoopReader();
    std::unique_ptr<CaptureFileReader> makeNetMonReader();
    std::unique_ptr<CaptureFileReader> makeErfReader();
    std::unique_ptr<CaptureFileReader> makeIptraceReader();

    /// A fresh reader for `format`, nullptr if the format has none.
    std::unique_ptr<CaptureFileReader> makeReader(FileFormat format);
} // namespace core::io
