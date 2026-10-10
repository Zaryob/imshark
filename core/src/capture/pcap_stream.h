#pragma once

// Incremental parser for a classic pcap byte stream (the format the capture worker writes into its FIFO).
// The stream comes from a process that is not trusted to be well behaved, so every field is validated before it
// is used: magic (both byte orders, microsecond and nanosecond variants), version, snaplen, link type and the
// header of every record (captured length <= snaplen and <= kMaxSnaplen, timestamp fraction in range).
// Nothing here touches the operating system: the owner feeds bytes with feed() as they arrive.

#include <cstddef>
#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace capture {
    /// Largest snapshot length that is accepted anywhere in the live capture path (header and every record).
    inline constexpr uint32_t kMaxStreamSnaplen = 262144;
    /// Smallest snapshot length the capture worker accepts as a command line argument.
    inline constexpr uint32_t kMinWorkerSnaplen = 64;

    struct PcapStreamHeader {
        bool bigEndian = false;       // multi byte fields are big endian
        bool nanosecond = false;      // the record timestamps carry nanoseconds
        uint32_t snaplen = 0;
        uint32_t linkType = 0;
    };

    class PcapStreamParser {
    public:
        /// One record. `data` is only valid during the callback. tsMicros is always microseconds (nanosecond streams are divided).
        using RecordFn = std::function<void(uint64_t tsSeconds, uint32_t tsMicros, const char *data, uint32_t capturedLength, uint32_t originalLength)>;
        using HeaderFn = std::function<bool(const PcapStreamHeader &)>;   // return false to refuse the stream

        PcapStreamParser(HeaderFn onHeader, RecordFn onRecord) : onHeader_(std::move(onHeader)), onRecord_(std::move(onRecord)) {}

        /// Consumes `size` bytes. Returns false (and sets error()) on the first invalid byte; the parser then refuses all
        /// further input. Records that were complete before the error have been delivered.
        bool feed(const char *data, size_t size);

        /// The stream ended (EOF). Returns false with an error text if it ended inside the header or a record.
        /// A stream that ends exactly on a record boundary is fine; one that never produced a header is an error.
        bool finish();

        bool headerSeen() const { return headerSeen_; }
        const PcapStreamHeader &header() const { return header_; }
        const std::string &error() const { return error_; }
        uint64_t recordCount() const { return records_; }
        uint64_t bytesConsumed() const { return consumed_; }

    private:
        bool fail(const std::string &text);
        bool parseHeader();
        bool parseRecordHeader();
        uint32_t u32(const char *p) const;
        uint16_t u16(const char *p) const;

        HeaderFn onHeader_;
        RecordFn onRecord_;
        PcapStreamHeader header_;
        bool headerSeen_ = false;
        bool failed_ = false;
        bool inRecord_ = false;                // the record header was read; its body is being collected
        uint32_t recSeconds_ = 0, recFraction_ = 0, recCaptured_ = 0, recOriginal_ = 0;
        std::vector<char> buffer_;             // bytes of the header / record header / record body still incomplete
        uint64_t records_ = 0, consumed_ = 0;
        std::string error_;
    };
} // namespace capture
