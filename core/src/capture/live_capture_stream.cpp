// The worker stream backend of LiveCapture: reads the classic pcap stream the capture worker writes into the private
// FIFO and feeds it through the same writeRecord/publish path as the libpcap capture thread. Also the glue that starts
// the worker through pkexec / osascript (startElevated). POSIX only; the Windows build gets stubs.

#include "live_capture.h"

#include "pcap_stream.h"

#include <chrono>
#include <cstring>
#include <system_error>

#ifndef _WIN32
#include <cerrno>
#include <fcntl.h>
#include <poll.h>
#include <sys/types.h>
#include <unistd.h>
#endif

namespace capture {
#ifdef _WIN32
    bool LiveCapture::startFromWorkerStream(int, const WorkerStreamOptions &) {
        stop();
        setError("Capturing through a helper process is not supported on this platform");
        return false;
    }

    bool LiveCapture::startElevated(const CaptureOptions &, const WorkerProcess::Spawner &) {
        stop();
        setError("Capturing through a helper process is not supported on this platform");
        return false;
    }

    bool LiveCapture::launchStreamThread(int, const WorkerStreamOptions &) { return false; }
    void LiveCapture::streamLoop(int, const WorkerStreamOptions &) {}
#else
    bool LiveCapture::launchStreamThread(int fd, const WorkerStreamOptions &options) {
        const int flags = ::fcntl(fd, F_GETFL);
        if (flags < 0 || ::fcntl(fd, F_SETFL, flags | O_NONBLOCK) != 0) {
            ::close(fd);
            setError("Cannot configure the capture pipe");
            return false;
        }
        ::fcntl(fd, F_SETFD, FD_CLOEXEC);
        stopRequested_ = false;
        running_ = true;
        authorizing_ = true;
        try {
            thread_ = std::thread([this, fd, options] {
                streamLoop(fd, options);
                publish();
                authorizing_ = false;
                if (fifo_) fifo_->remove();     // the session is over: nothing is left behind (stop() and the destructor repeat it)
                running_ = false;
            });
        } catch (const std::system_error &e) {
            ::close(fd);
            running_ = false;
            authorizing_ = false;
            setError(std::string("Cannot start the capture thread: ") + e.what());
            return false;
        }
        return true;
    }

    bool LiveCapture::startFromWorkerStream(int fd, const WorkerStreamOptions &options) {
        stop();
        removeTemp();
        resetSession();
        return launchStreamThread(fd, options);
    }

    void LiveCapture::streamLoop(int fd, const WorkerStreamOptions &options) {
        PcapStreamParser parser(
            [this](const PcapStreamHeader &h) {
                if (!openFile(h.linkType, h.snaplen)) return false;   // openFile set the error
                streaming_ = true;
                authorizing_ = false;
                return true;
            },
            [this](uint64_t sec, uint32_t usec, const char *data, uint32_t captured, uint32_t original) {
                writeRecord(sec, usec, data, captured, original);
            });

        std::string error;
        bool eof = false;
        bool producerSeenGone = false;
        const auto started = std::chrono::steady_clock::now();
        std::vector<char> buffer(64 * 1024);
        while (!stopRequested_ && !writeFailed_) {
            // asked before the read: whatever the process wrote before it ended is still read below
            const bool gone = options.producerGone && options.producerGone();
            const ssize_t n = ::read(fd, buffer.data(), buffer.size());
            if (n > 0) {
                if (!parser.feed(buffer.data(), static_cast<size_t>(n))) {
                    error = parser.error();
                    break;
                }
                publish();
                continue;
            }
            if (n < 0 && errno == EINTR) continue;
            if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
                error = std::string("Reading from the capture helper failed: ") + std::strerror(errno);
                break;
            }
            if (n == 0 && parser.bytesConsumed() > 0) {
                eof = true;
                break;
            }
            // Nothing to read. n == 0 without data: no writer has opened the FIFO yet (or one closed without writing).
            if (gone && parser.bytesConsumed() == 0) {
                if (producerSeenGone) {
                    error = "The capture helper ended without sending any data";
                    break;
                }
                producerSeenGone = true;     // one more pass: bytes written just before it ended may still be on their way
            }
            if (!parser.headerSeen() &&
                std::chrono::steady_clock::now() - started > std::chrono::milliseconds(options.connectTimeoutMs)) {
                error = "Timed out waiting for the capture helper to start";
                break;
            }
            if (n == 0) {
                std::this_thread::sleep_for(std::chrono::milliseconds(20));
            } else {
                pollfd p{fd, POLLIN, 0};
                ::poll(&p, 1, 50);
            }
        }
        ::close(fd);      // the helper sees EPIPE / a closed reader now and ends
        if (stopRequested_) return;
        if (eof && !parser.finish()) error = parser.error();
        publish();
        if (options.finalize) error = options.finalize(error);
        if (!error.empty()) setError(error);
    }

    bool LiveCapture::startElevated(const CaptureOptions &options, const WorkerProcess::Spawner &spawner) {
        stop();
        removeTemp();
        resetSession();
        if (!liveCaptureAvailable()) {
            setError(kNotAvailable);
            return false;
        }
        const ElevationMethod method = platformElevationMethod();
        if (method == ElevationMethod::None) {
            setError("Capturing with administrator authorization is not available on this platform; see the permanent setup instructions");
            return false;
        }
        if (options.interfaceName.empty()) {
            setError("No capture interface selected");
            return false;
        }
        if (options.snaplen < kMinWorkerSnaplen || options.snaplen > kMaxStreamSnaplen) {
            setError("The snapshot length must be between " + std::to_string(kMinWorkerSnaplen) + " and " + std::to_string(kMaxStreamSnaplen) + " bytes");
            return false;
        }
        if (::getuid() == 0) {
            setError("ImShark is running as root but still cannot open the interface");
            return false;
        }
        const std::string exe = currentExecutablePath();
        if (exe.empty() || exe[0] != '/') {
            setError("Cannot determine the path of the ImShark executable");
            return false;
        }
        auto fifo = std::make_unique<PrivateFifo>();
        std::string error;
        if (!fifo->create(error)) {
            setError(error);
            return false;
        }
        // The reading end is opened first (non blocking, succeeds without a writer), so the worker's open never has to wait.
        const int fd = ::open(fifo->path().c_str(), O_RDONLY | O_NONBLOCK | O_CLOEXEC);
        if (fd < 0) {
            setError(std::string("Cannot open the capture pipe: ") + std::strerror(errno));
            return false;                   // ~PrivateFifo removes the directory
        }
        worker::WorkerArgs args;
        args.interfaceName = options.interfaceName;
        args.snaplen = options.snaplen;
        args.promiscuous = options.promiscuous;
        args.filter = options.filter;
        args.uid = static_cast<uint32_t>(::getuid());
        args.gid = static_cast<uint32_t>(::getgid());
        args.fifoPath = fifo->path();
        fifo_ = std::move(fifo);
        worker_ = std::make_unique<WorkerProcess>();
        worker_->start(buildElevationArgv(method, exe, worker::workerCommandLine(args)), spawner);

        WorkerStreamOptions stream;
        WorkerProcess *process = worker_.get();     // outlives the reader thread: stop() joins it before releasing the process
        stream.producerGone = [process] { return process->exited(); };
        stream.finalize = [process, method](const std::string &readerError) {
            process->waitExit(1500);
            if (process->exited()) {
                const std::string why = describeWorkerFailure(method, process->status(), process->stderrText());
                if (!why.empty()) return why;
            }
            return readerError;
        };
        if (!launchStreamThread(fd, stream)) {
            worker_->abandon();
            worker_.reset();
            fifo_->remove();
            fifo_.reset();
            return false;
        }
        return true;
    }
#endif
} // namespace capture
