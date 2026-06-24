#pragma once

// The capture file reader interface (ROADMAP B5). A CaptureFileReader turns the bytes of one capture file format
// into a stream of records; FileProcessor::load() (core.cpp) drives it and does everything that is the same for all
// formats (time base, packet summaries, reassembly annotations, progress, session tables). The readers are picked by
// the registry in io/format_registry.h from the magic number of the file.
//
// Framing differs between formats, and the interface leaves room for that:
//  - open() receives the stream positioned at the start and may read, seek and look at the end as it likes: a pcap
//    reader reads a 24 byte header, a pcapng reader nothing yet (its first block is a record-like block), an ERF
//    reader nothing at all (ERF has no file header, the first record starts at offset 0) and a Network Monitor
//    reader seeks to the frame table at the end of the file and walks it from there (the frames are in the middle).
//  - next() returns one record at a time. What sits between two records (pcapng metadata blocks, ERF extension
//    headers and padding, snoop record padding) is the reader's business; it only reports the byte offset of the
//    frame (`fileOffset`) and its captured length, which is all that Replay needs to read one packet again
//    (core::readPacketBytes / CaptureReader seek there and read `captured_length` bytes).
//  - the link type, the timestamp resolution and the FCS length are per record, because ERF and pcapng change
//    them from record to record; a reader that learns about interfaces as it goes appends them to the capture info.

#include <cstdint>
#include <iosfwd>
#include <memory>
#include <string>
#include <vector>

#include <capture_info.h>
#include <load_control.h>
#include <dissect/session.h>

namespace core::io {
    /// One captured frame as a reader hands it over. The driver reuses the object (and the frame buffer's capacity)
    /// for every record, so a reader sets every field on every call.
    struct CaptureRecord {
        std::vector<char> frame;             // the captured bytes (captured length = frame.size())
        uint64_t fileOffset = 0;             // where those bytes start in the file
        uint32_t originalLength = 0;         // length on the wire
        uint32_t linkType = 1;               // LINKTYPE_* (packet::kUndefinedLinkType if the file does not say)
        uint8_t fcsLength = 0;               // FCS bytes at the end of the frame (0 = unknown / none)
        bool hasTimestamp = true;            // false: the format carries none for this record (pcapng simple packet), the previous time is reused
        uint64_t seconds = 0;                // timestamp: whole seconds (interface offset already added) ...
        uint64_t fraction = 0;               // ... plus `fraction` ticks of 1 / ticksPerSecond
        uint64_t ticksPerSecond = 1'000'000;
        int interfaceIndex = -1;             // index into CaptureInfo::interfaces whose packet counter this record increments, -1 = none
        std::string comment;                 // packet comment stored with the record (empty = none)
    };

    /// Describes why a reader stopped, and (for End) a warning that goes with a normal end.
    struct ReadIssue {
        std::string message;
        bool keepRecords = false;            // Error only: the records read so far stay loaded and the load counts as successful
    };

    /// Where the driver gives a reader access to the capture-wide state it fills.
    struct ReaderContext {
        CaptureInfo &info;                   // format, interfaces, names, comments, secrets
        dissect::SessionTables &sessions;    // decryption secrets found in the file go to its key store
        uint64_t fileSize = 0;
    };

    class CaptureFileReader {
    public:
        virtual ~CaptureFileReader() = default;

        /// Reads whatever the format has before its first record and fills `ctx.info`. `in` is positioned at offset 0
        /// and stays valid for the life of the reader. Returns false with `message` on a file that is not this format.
        virtual bool open(std::istream &in, ReaderContext &ctx, std::string &message) = 0;

        enum class Status {
            Record,   // `rec` holds the next frame
            End,      // the last record was read (issue.message may carry a warning, e.g. a truncated final record)
            Error,    // the file is damaged; issue.message says how and issue.keepRecords whether the load still succeeds
        };
        virtual Status next(CaptureRecord &rec, ReadIssue &issue) = 0;

        /// File offset one past everything consumed so far (progress reporting).
        virtual uint64_t bytesConsumed() const = 0;

        /// Called once after End, with the driver's message so far; a reader may append problems that are only known
        /// once the whole file has been seen (pcapng: packets of undefined interfaces).
        virtual void finish(std::string &message) { (void) message; }

        /// Smallest size of one record in the file (record header plus the smallest frame): the driver sizes the
        /// packet vector with it.
        virtual uint64_t minRecordBytes() const = 0;
    };

    using ReaderFactory = std::unique_ptr<CaptureFileReader> (*)();
} // namespace core::io
