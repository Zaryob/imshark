#include "live_capture.h"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstring>
#include <filesystem>
#include <system_error>

#include <temp_file.h>

namespace capture {
    namespace {
        void put16(std::string &out, uint16_t v) { for (int i = 0; i < 2; ++i) out += static_cast<char>((v >> (8 * i)) & 0xff); }
        void put32(std::string &out, uint32_t v) { for (int i = 0; i < 4; ++i) out += static_cast<char>((v >> (8 * i)) & 0xff); }

        constexpr uint64_t kFileHeaderSize = 24, kRecordHeaderSize = 16;

        std::string makeTempPath() { return core::createTempFile(".pcap"); }   // exclusive, 0600, in a private dir
    } // namespace

    LiveCapture::LiveCapture() = default;

    LiveCapture::~LiveCapture() {
        stop();
        removeTemp();
    }

    std::string LiveCapture::workerFifoPath() const {
        return fifo_ ? fifo_->path() : std::string();
    }

    std::string LiveCapture::lastError() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return error_;
    }

    std::string LiveCapture::tempPath() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return path_;
    }

    void LiveCapture::setError(const std::string &text) {
        std::lock_guard<std::mutex> lock(mutex_);
        error_ = text;
    }

    void LiveCapture::removeTemp() {
        std::string path;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (released_) return;
            path = path_;
        }
        if (path.empty()) return;
        std::error_code ec;
        std::filesystem::remove(core::pathFromUtf8(path), ec);
    }

    std::string LiveCapture::releaseTempFile() {
        std::lock_guard<std::mutex> lock(mutex_);
        released_ = true;
        return path_;
    }

    void LiveCapture::resetSession() {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            queue_.clear();
            error_.clear();
            path_.clear();
            released_ = false;
        }
        permissionDenied_ = false;
        authorizing_ = false;
        streaming_ = false;
        std::lock_guard<std::mutex> writer(writerMutex_);
        pending_.clear();
        fileSize_ = 0;
        packetCount_ = 0;
        dropped_ = 0;
        writeFailed_ = false;
    }

    // A write to the temp file failed: nothing more can be recorded, so the capture ends here. The error text stays in
    // lastError() and running() turns false (the capture thread notices stopRequested_ / the breakloop and exits).
    void LiveCapture::failWrite(const std::string &text) {
        setError(text);
        writeFailed_ = true;
        stopRequested_ = true;
        running_ = false;
        breakCapture();
    }

    bool LiveCapture::openFile(uint32_t linkType, uint32_t snaplen) {
        const std::string path = makeTempPath();
        std::lock_guard<std::mutex> writer(writerMutex_);
        file_.close();
        file_.clear();
        file_.open(core::pathFromUtf8(path), std::ios::binary | std::ios::trunc);
        if (!file_) {
            setError("Cannot create the temporary capture file " + path);
            return false;
        }
        std::string head;
        put32(head, 0xa1b2c3d4);     // classic pcap, microsecond timestamps
        put16(head, 2);
        put16(head, 4);
        put32(head, 0);              // thiszone
        put32(head, 0);              // sigfigs
        put32(head, snaplen);
        put32(head, linkType);
        file_.write(head.data(), static_cast<std::streamsize>(head.size()));
        file_.flush();
        if (!file_) {
            setError("Writing to the temporary capture file " + path + " failed");
            file_.close();
            std::error_code ec;
            std::filesystem::remove(core::pathFromUtf8(path), ec);
            return false;
        }
        fileSize_ = kFileHeaderSize;
        linkType_ = linkType;
        snaplen_ = snaplen;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            path_ = path;
        }
        return true;
    }

    // Called with the file open; takes the writer lock itself.
    bool LiveCapture::writeRecord(uint64_t tsSeconds, uint32_t tsMicros, const char *data, uint32_t capturedLength, uint32_t originalLength) {
        std::lock_guard<std::mutex> writer(writerMutex_);
        if (!file_.is_open() || writeFailed_) return false;
        std::string rec;
        rec.reserve(kRecordHeaderSize);
        put32(rec, static_cast<uint32_t>(tsSeconds));
        put32(rec, tsMicros);
        put32(rec, capturedLength);
        put32(rec, std::max(originalLength, capturedLength));
        file_.write(rec.data(), static_cast<std::streamsize>(rec.size()));
        file_.write(data, capturedLength);
        if (!file_) {
            failWrite("Writing to the temporary capture file failed (disk full?)");
            return false;
        }
        CapturedPacket p;
        p.fileOffset = fileSize_ + kRecordHeaderSize;
        p.capturedLength = capturedLength;
        p.originalLength = std::max(originalLength, capturedLength);
        p.tsSeconds = tsSeconds;
        p.tsMicros = tsMicros;
        p.linkType = linkType_;
        fileSize_ += kRecordHeaderSize + capturedLength;
        pending_.push_back(p);
        ++packetCount_;
        return true;
    }

    void LiveCapture::publish() {
        std::lock_guard<std::mutex> writer(writerMutex_);
        if (pending_.empty()) return;
        file_.flush();   // the consumer reads the frames back from the file: they must be there before it hears of them
        if (!file_) {
            packetCount_ -= pending_.size();   // their bytes did not reach the file: they are neither announced nor counted
            pending_.clear();
            failWrite("Writing to the temporary capture file failed (disk full?)");
            return;
        }
        std::lock_guard<std::mutex> lock(mutex_);
        queue_.insert(queue_.end(), pending_.begin(), pending_.end());
        pending_.clear();
    }

    size_t LiveCapture::takePackets(std::vector<CapturedPacket> &out, size_t maxCount) {
        std::lock_guard<std::mutex> lock(mutex_);
        const size_t n = maxCount ? std::min(maxCount, queue_.size()) : queue_.size();
        out.insert(out.end(), queue_.begin(), queue_.begin() + static_cast<std::ptrdiff_t>(n));
        queue_.erase(queue_.begin(), queue_.begin() + static_cast<std::ptrdiff_t>(n));
        return n;
    }

    bool LiveCapture::start(const CaptureOptions &options) {
        stop();
        removeTemp();
        resetSession();
        if (!liveCaptureAvailable()) {
            setError(kNotAvailable);
            return false;
        }
        uint32_t linkType = 1;
        std::string error;
        if (!openDevice(options, linkType, error)) {
            setError(error);
            return false;
        }
        if (!openFile(linkType, options.snaplen)) {
            closeDevice();
            return false;
        }
        stopRequested_ = false;
        running_ = true;
        try {
            thread_ = std::thread([this] {
                captureLoop();
                publish();
                running_ = false;
            });
        } catch (const std::system_error &e) {
            running_ = false;
            closeDevice();
            setError(std::string("Cannot start the capture thread: ") + e.what());
            return false;
        }
        return true;
    }

    void LiveCapture::stop() {
        stopRequested_ = true;
        breakCapture();
        if (thread_.joinable()) thread_.join();
        closeDevice();
        publish();
        {
            std::lock_guard<std::mutex> writer(writerMutex_);
            if (file_.is_open()) {
                file_.flush();
                file_.close();
            }
        }
        running_ = false;
        authorizing_ = false;
        if (worker_) {          // the reader thread is joined: the FIFO read end is closed, the helper sees EPIPE and ends
            worker_->abandon();
            worker_.reset();
        }
        if (fifo_) {
            fifo_->remove();
            fifo_.reset();
        }
    }

    bool LiveCapture::beginInjected(uint32_t linkType, uint32_t snaplen) {
        stop();
        removeTemp();
        resetSession();
        if (!openFile(linkType, snaplen)) return false;
        stopRequested_ = false;
        running_ = true;       // an injected session runs until stop() or a write failure, like a real capture
        return true;
    }

    bool LiveCapture::injectPacket(uint64_t tsSeconds, uint32_t tsMicros, const std::vector<char> &frame, uint32_t originalLength) {
        const uint32_t captured = static_cast<uint32_t>(std::min<size_t>(frame.size(), snaplen_));
        const bool written = writeRecord(tsSeconds, tsMicros, frame.data(), captured, originalLength ? originalLength : static_cast<uint32_t>(frame.size()));
        publish();
        return written && !writeFailed_;
    }

    size_t appendCapturedPackets(LiveCapture &live, core::FileProcessor &processor, std::vector<packet::PacketInfo> &packets,
                                 size_t maxPackets, std::vector<uint32_t> *amended) {
        std::vector<CapturedPacket> batch;
        if (live.takePackets(batch, maxPackets) == 0) return 0;
        if (processor.captureInfo().interfaces.empty()) processor.beginLive(live.linkType(), live.snaplen());

        const std::string path = live.tempPath();
        std::ifstream file(core::pathFromUtf8(path), std::ios::binary);
        size_t appended = 0;
        std::vector<char> frame;
        for (const CapturedPacket &p: batch) {
            frame.resize(p.capturedLength);
            file.clear();
            file.seekg(static_cast<std::streamoff>(p.fileOffset));
            if (p.capturedLength > 0 && !file.read(frame.data(), p.capturedLength)) {
                live.setError("Cannot read captured packets back from " + path);
                continue;
            }
            processor.appendLivePacket(packets, p.tsSeconds, p.tsMicros, p.linkType, p.fileOffset, p.originalLength, frame, amended);
            ++appended;
        }
        return appended;
    }
} // namespace capture
