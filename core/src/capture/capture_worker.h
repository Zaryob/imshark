#pragma once

// The capture worker: `imshark --capture-worker ...`. A tiny headless mode of the imshark executable that the GUI
// starts through pkexec (Linux) or osascript (macOS) when the GUI itself may not open the capture device.
//
//   * it opens the capture device and compiles the filter while it still has the administrator rights,
//   * then it irrevocably drops them to the uid/gid of the user who started the GUI (setgroups, setgid, setuid,
//     verified; Linux additionally PR_SET_NO_NEW_PRIVS and PR_SET_PDEATHSIG),
//   * only after that does it open the FIFO the GUI created (as the unprivileged user: O_NOFOLLOW, must be a FIFO
//     owned by that user) and stream a classic pcap into it.
// It never writes a file as root, changes no permissions and reads no environment variable. docs/CAPTURE_PRIVILEGES.md
// describes the whole design.
//
// Everything here is split so that it can be tested without privileges and without a device: the argument parser,
// the packet source interface and the stream loop (streamCapture) do not depend on libpcap.

#include <atomic>
#include <csignal>
#include <cstdint>
#include <string>
#include <vector>

namespace capture::worker {
    /// Process exit codes of the worker (one distinct code per failure class; the GUI shows the stderr line).
    enum ExitCode : int {
        kExitOk = 0,
        kExitUsage = 2,            // invalid / missing / duplicate / unknown arguments
        kExitNoSuchInterface = 3,  // the interface is not in pcap_findalldevs
        kExitOpenFailed = 4,       // pcap_create / pcap_activate failed
        kExitPermission = 5,       // ... because of missing privileges (the worker was not started with admin rights)
        kExitFilter = 6,           // invalid BPF filter
        kExitDropFailed = 7,       // the privileges could not be dropped (or the target uid/gid is unacceptable)
        kExitFifo = 8,             // the FIFO is missing, not a FIFO, not owned by the user, ...
        kExitCapture = 9,          // the capture failed while running (device vanished, ...)
        kExitUnsupported = 10,     // built without live capture / platform without a worker
    };

    /// The command line of the worker, after `--capture-worker`:
    ///   --interface <name> --snaplen <64..262144> --promisc <0|1> --filter <bpf, may be empty> --uid <n> --gid <n> --fifo <absolute path>
    /// Every flag exactly once; every value is taken verbatim (no quoting, no expansion).
    struct WorkerArgs {
        std::string interfaceName;
        uint32_t snaplen = 0;
        bool promiscuous = false;
        std::string filter;
        uint32_t uid = 0, gid = 0;
        std::string fifoPath;
    };

    struct ParseResult {
        bool ok = false;
        WorkerArgs args;
        std::string error;         // one line, empty if ok
    };

    /// Strict parser: unknown flag, duplicate, missing flag or value, non numeric / out of range number, uid or gid 0,
    /// a relative or oversized FIFO path, an empty or oversized interface name are all errors.
    ParseResult parseWorkerArgs(const std::vector<std::string> &args);

    /// The flag list the GUI passes (`--capture-worker` first), the exact inverse of parseWorkerArgs. Each value is its own element.
    std::vector<std::string> workerCommandLine(const WorkerArgs &args);

    // ---- stream loop (testable) --------------------------------------------------------------------------------------
    struct SourcePacket {
        uint64_t tsSeconds = 0;
        uint32_t tsMicros = 0;
        const unsigned char *data = nullptr;
        uint32_t capturedLength = 0;
        uint32_t originalLength = 0;
    };

    /// Where the packets come from: libpcap in production, a script in the tests.
    class PacketSource {
    public:
        enum class Status { Packet, Timeout, Error, End };
        virtual ~PacketSource() = default;
        /// Waits at most about 250 ms. Packet: `out` is filled (valid until the next call). Timeout: nothing arrived.
        virtual Status next(SourcePacket &out) = 0;
        virtual std::string error() const { return {}; }
    };

    enum class StreamEnd {
        Stopped,        // the stop flag was set (SIGTERM / SIGINT)
        ReaderGone,     // the GUI closed its end (EPIPE, POLLERR/POLLHUP, FIFO unlinked)
        SourceEnded,    // the packet source reported End
        SourceError,    // the packet source failed (error text in `error`)
        WriteError,     // a write failed for another reason (error text in `error`)
    };

    /// Writes the pcap global header (little endian, microsecond magic, the real link type and snaplen) and then every
    /// packet of `source` to `fd`, truncating nothing but never writing more than `snaplen` bytes of a packet. Between
    /// packets and on every source timeout it checks `stop`; on every timeout it also checks that the reader is still
    /// there. SIGPIPE must be ignored by the caller (a closed reader is then EPIPE). Does not close `fd`.
    /// POSIX only: returns SourceError ("not supported") on Windows.
    StreamEnd streamCapture(int fd, PacketSource &source, uint32_t linkType, uint32_t snaplen, const volatile std::sig_atomic_t *stop,
                            std::string &error, bool watchUnlink = false);

    /// true if the process cannot reach the other end any more: poll() reports POLLERR/POLLHUP/POLLNVAL on `fd`, or (with
    /// `watchUnlink`, for a named FIFO) the FIFO was unlinked, which is what the GUI does when the capture ends - macOS does
    /// not report a closed reader of an idle FIFO through poll(). POSIX only (false on Windows).
    bool peerGone(int fd, bool watchUnlink = false);

    /// Opens `path` for writing as the current (unprivileged) user and checks it: O_WRONLY | O_NOFOLLOW | O_CLOEXEC, no
    /// blocking while no reader is there (retries for up to `timeoutMs`), then fstat must say FIFO owned by `expectedUid`.
    /// Returns the (blocking) fd or -1 with `error` set. POSIX only.
    int openFifoForWriting(const std::string &path, uint32_t expectedUid, const volatile std::sig_atomic_t *stop, int timeoutMs, std::string &error);

    /// Entry point of `imshark --capture-worker`: `args` are the arguments after the flag. Returns the process exit code
    /// and prints one line on stderr on failure. Call it before any window system initialisation.
    int runCaptureWorker(const std::vector<std::string> &args);
} // namespace capture::worker
