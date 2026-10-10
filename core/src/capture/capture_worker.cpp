#include "capture_worker.h"

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <thread>

#include "pcap_stream.h"

#ifndef _WIN32
#include <fcntl.h>
#include <grp.h>
#include <poll.h>
#include <signal.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#ifdef __linux__
#include <sys/prctl.h>
#endif
extern char **environ;
#endif

#ifdef IMSHARK_HAVE_LIVE_CAPTURE
#include <pcap.h>
#endif

namespace capture::worker {
    namespace {
        constexpr size_t kMaxInterfaceName = 255;
        constexpr size_t kMaxFilterLength = 8192;
        constexpr size_t kMaxPathLength = 1024;

        bool parseNumber(const std::string &text, uint64_t maxValue, uint64_t &out) {
            if (text.empty() || text.size() > 10) return false;
            uint64_t v = 0;
            for (char c: text) {
                if (c < '0' || c > '9') return false;
                v = v * 10 + static_cast<uint64_t>(c - '0');
            }
            if (v > maxValue) return false;
            out = v;
            return true;
        }

        [[maybe_unused]] void put16(std::string &out, uint16_t v) { for (int i = 0; i < 2; ++i) out += static_cast<char>((v >> (8 * i)) & 0xff); }
        [[maybe_unused]] void put32(std::string &out, uint32_t v) { for (int i = 0; i < 4; ++i) out += static_cast<char>((v >> (8 * i)) & 0xff); }

        int fail(int code, const std::string &message) {
            std::fprintf(stderr, "imshark-capture-worker: %s\n", message.c_str());
            return code;
        }
    } // namespace

    // ---- arguments ---------------------------------------------------------------------------------------------------
    ParseResult parseWorkerArgs(const std::vector<std::string> &args) {
        ParseResult result;
        auto bad = [&](const std::string &text) {
            result.ok = false;
            result.error = text;
            return result;
        };
        const char *const names[] = {"--interface", "--snaplen", "--promisc", "--filter", "--uid", "--gid", "--fifo"};
        bool seen[7] = {false, false, false, false, false, false, false};
        WorkerArgs a;
        if (args.size() % 2 != 0) {
            // a flag without its value (or a stray value): name the last element
            return bad("missing value for " + args.back());
        }
        for (size_t i = 0; i < args.size(); i += 2) {
            const std::string &flag = args[i];
            const std::string &value = args[i + 1];
            size_t index = 7;
            for (size_t k = 0; k < 7; ++k) {
                if (flag == names[k]) index = k;
            }
            if (index == 7) return bad("unknown argument: " + (flag.size() > 64 ? flag.substr(0, 64) + "..." : flag));
            if (seen[index]) return bad(std::string("duplicate argument ") + names[index]);
            seen[index] = true;
            uint64_t n = 0;
            switch (index) {
                case 0:
                    if (value.empty() || value.size() > kMaxInterfaceName) return bad("invalid --interface");
                    a.interfaceName = value;
                    break;
                case 1:
                    if (!parseNumber(value, kMaxStreamSnaplen, n) || n < kMinWorkerSnaplen) {
                        return bad("--snaplen must be a number from " + std::to_string(kMinWorkerSnaplen) + " to " + std::to_string(kMaxStreamSnaplen));
                    }
                    a.snaplen = static_cast<uint32_t>(n);
                    break;
                case 2:
                    if (value != "0" && value != "1") return bad("--promisc must be 0 or 1");
                    a.promiscuous = value == "1";
                    break;
                case 3:
                    if (value.size() > kMaxFilterLength) return bad("--filter is too long");
                    a.filter = value;
                    break;
                case 4:
                    if (!parseNumber(value, 0xfffffffeu, n) || n == 0) return bad("--uid must be a number greater than 0");
                    a.uid = static_cast<uint32_t>(n);
                    break;
                case 5:
                    if (!parseNumber(value, 0xfffffffeu, n) || n == 0) return bad("--gid must be a number greater than 0");
                    a.gid = static_cast<uint32_t>(n);
                    break;
                case 6:
                    if (value.empty() || value.size() > kMaxPathLength || value.front() != '/') return bad("--fifo must be an absolute path");
                    a.fifoPath = value;
                    break;
                default:
                    break;     // unreachable: index < 7 here
            }
        }
        for (size_t k = 0; k < 7; ++k) {
            if (!seen[k]) return bad(std::string("missing argument ") + names[k]);
        }
        result.ok = true;
        result.args = std::move(a);
        return result;
    }

    std::vector<std::string> workerCommandLine(const WorkerArgs &a) {
        return {"--capture-worker",
                "--interface", a.interfaceName,
                "--snaplen", std::to_string(a.snaplen),
                "--promisc", a.promiscuous ? "1" : "0",
                "--filter", a.filter,
                "--uid", std::to_string(a.uid),
                "--gid", std::to_string(a.gid),
                "--fifo", a.fifoPath};
    }

#ifdef _WIN32
    // ---- Windows: no worker -----------------------------------------------------------------------------------------
    StreamEnd streamCapture(int, PacketSource &, uint32_t, uint32_t, const volatile std::sig_atomic_t *, std::string &error, bool) {
        error = "The capture worker is not supported on this platform";
        return StreamEnd::SourceError;
    }
    bool peerGone(int, bool) { return false; }
    int openFifoForWriting(const std::string &, uint32_t, const volatile std::sig_atomic_t *, int, std::string &error) {
        error = "The capture worker is not supported on this platform";
        return -1;
    }
    int runCaptureWorker(const std::vector<std::string> &args) {
        const ParseResult parsed = parseWorkerArgs(args);
        if (!parsed.ok) return fail(kExitUsage, parsed.error);
        return fail(kExitUnsupported, "the capture worker is not supported on this platform");
    }
#else
    // ---- POSIX stream loop --------------------------------------------------------------------------------------------
    namespace {
        enum class WriteResult { Ok, ReaderGone, Interrupted, Error };

        WriteResult writeAll(int fd, const char *data, size_t size, const volatile std::sig_atomic_t *stop, std::string &error) {
            size_t done = 0;
            while (done < size) {
                const ssize_t n = ::write(fd, data + done, size - done);
                if (n > 0) {
                    done += static_cast<size_t>(n);
                    continue;
                }
                if (n < 0 && errno == EINTR) {
                    if (stop && *stop) return WriteResult::Interrupted;
                    continue;
                }
                if (n < 0 && errno == EPIPE) return WriteResult::ReaderGone;
                if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                    if (stop && *stop) return WriteResult::Interrupted;
                    pollfd p{fd, POLLOUT, 0};
                    ::poll(&p, 1, 100);
                    if (p.revents & (POLLERR | POLLHUP | POLLNVAL)) return WriteResult::ReaderGone;
                    continue;
                }
                error = std::string("write failed: ") + std::strerror(errno);
                return WriteResult::Error;
            }
            return WriteResult::Ok;
        }
    } // namespace

    bool peerGone(int fd, bool watchUnlink) {
        pollfd p{fd, POLLOUT, 0};
        if (::poll(&p, 1, 0) > 0 && (p.revents & (POLLERR | POLLHUP | POLLNVAL))) return true;
        if (watchUnlink) {
            struct stat st {};
            if (::fstat(fd, &st) == 0 && st.st_nlink == 0) return true;
        }
        return false;
    }

    StreamEnd streamCapture(int fd, PacketSource &source, uint32_t linkType, uint32_t snaplen, const volatile std::sig_atomic_t *stop,
                            std::string &error, bool watchUnlink) {
        std::string head;
        put32(head, 0xa1b2c3d4);     // classic pcap, little endian, microsecond timestamps
        put16(head, 2);
        put16(head, 4);
        put32(head, 0);
        put32(head, 0);
        put32(head, snaplen);
        put32(head, linkType);
        auto map = [&](WriteResult r) -> int {   // -1 continue, otherwise a StreamEnd value
            switch (r) {
                case WriteResult::Ok: return -1;
                case WriteResult::ReaderGone: return static_cast<int>(StreamEnd::ReaderGone);
                case WriteResult::Interrupted: return static_cast<int>(StreamEnd::Stopped);
                case WriteResult::Error: return static_cast<int>(StreamEnd::WriteError);
            }
            return static_cast<int>(StreamEnd::WriteError);
        };
        if (const int e = map(writeAll(fd, head.data(), head.size(), stop, error)); e >= 0) return static_cast<StreamEnd>(e);

        std::string record;
        SourcePacket packet;
        while (true) {
            if (stop && *stop) return StreamEnd::Stopped;
            switch (source.next(packet)) {
                case PacketSource::Status::Packet: {
                    const uint32_t captured = std::min(packet.capturedLength, snaplen);
                    record.clear();
                    put32(record, static_cast<uint32_t>(packet.tsSeconds));
                    put32(record, packet.tsMicros);
                    put32(record, captured);
                    put32(record, std::max(packet.originalLength, captured));
                    record.append(reinterpret_cast<const char *>(packet.data), captured);
                    if (const int e = map(writeAll(fd, record.data(), record.size(), stop, error)); e >= 0) return static_cast<StreamEnd>(e);
                    break;
                }
                case PacketSource::Status::Timeout:
                    if (peerGone(fd, watchUnlink)) return StreamEnd::ReaderGone;
                    break;
                case PacketSource::Status::End: return StreamEnd::SourceEnded;
                case PacketSource::Status::Error:
                    error = source.error();
                    return StreamEnd::SourceError;
            }
        }
    }

    int openFifoForWriting(const std::string &path, uint32_t expectedUid, const volatile std::sig_atomic_t *stop, int timeoutMs, std::string &error) {
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeoutMs);
        int fd = -1;
        while (true) {
            // O_NONBLOCK: a write-only open of a FIFO blocks until a reader exists; without a reader it fails with ENXIO instead
            fd = ::open(path.c_str(), O_WRONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC);
            if (fd >= 0) break;
            if (errno != ENXIO || (stop && *stop) || std::chrono::steady_clock::now() >= deadline) {
                error = "cannot open the capture pipe: " + std::string(errno == ENXIO ? "nobody is reading it" : std::strerror(errno));
                return -1;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(25));
        }
        struct stat st {};
        if (::fstat(fd, &st) != 0 || !S_ISFIFO(st.st_mode)) {
            error = "the capture pipe is not a FIFO";
            ::close(fd);
            return -1;
        }
        if (st.st_uid != static_cast<uid_t>(expectedUid)) {
            error = "the capture pipe is not owned by the capturing user";
            ::close(fd);
            return -1;
        }
        const int flags = ::fcntl(fd, F_GETFL);
        if (flags < 0 || ::fcntl(fd, F_SETFL, flags & ~O_NONBLOCK) != 0) {
            error = "cannot configure the capture pipe";
            ::close(fd);
            return -1;
        }
        return fd;
    }

#ifdef IMSHARK_HAVE_LIVE_CAPTURE
    // ---- the worker proper (needs libpcap) --------------------------------------------------------------------------
    namespace {
        volatile std::sig_atomic_t g_stop = 0;

        extern "C" void onStopSignal(int) { g_stop = 1; }

        void installSignals() {
            struct sigaction sa {};
            sa.sa_handler = onStopSignal;
            sigemptyset(&sa.sa_mask);
            sa.sa_flags = 0;               // no SA_RESTART: a blocked write() or poll() must return EINTR
            sigaction(SIGTERM, &sa, nullptr);
            sigaction(SIGINT, &sa, nullptr);
            sigaction(SIGHUP, &sa, nullptr);
            struct sigaction ign {};
            ign.sa_handler = SIG_IGN;
            sigemptyset(&ign.sa_mask);
            sigaction(SIGPIPE, &ign, nullptr);     // a closed reader is EPIPE, not death
        }

        // The environment is attacker influenced input of a privileged program: nothing in it is trusted, so it is dropped.
        void clearEnvironment() {
            static char *empty[] = {nullptr};
            environ = empty;
        }

        uint32_t dltToLinkType(int dlt) {
#ifdef DLT_RAW
            if (dlt == DLT_RAW) return 101;
#endif
#ifdef DLT_LOOP
            if (dlt == DLT_LOOP) return 108;
#endif
            return static_cast<uint32_t>(dlt);
        }

        bool interfaceExists(const std::string &name, std::string &error) {
            char errbuf[PCAP_ERRBUF_SIZE] = {0};
            pcap_if_t *devices = nullptr;
            if (pcap_findalldevs(&devices, errbuf) != 0) {
                error = std::string("cannot list the capture interfaces: ") + errbuf;
                return false;
            }
            bool found = false;
            for (const pcap_if_t *d = devices; d && !found; d = d->next) found = d->name && name == d->name;
            pcap_freealldevs(devices);
            if (!found) error = "no such capture interface";
            return found;
        }

        // Irrevocable: group list emptied, gid, then uid (the order matters: setgid needs the root uid), then verified.
        bool dropPrivileges(uint32_t uid, uint32_t gid, pid_t parentBefore, std::string &error) {
            if (::geteuid() != 0 && ::getuid() != 0) {
                // nothing to drop: this is a run as the unprivileged user itself (tests, a user with device access)
                if (::getuid() != uid || ::geteuid() != uid || ::getgid() != gid || ::getegid() != gid) {
                    error = "not running as root, so --uid/--gid must be the current user's";
                    return false;
                }
                return true;
            }
            if (uid == 0 || gid == 0) {
                error = "refusing to drop to uid 0 / gid 0";
                return false;
            }
            if (::setgroups(0, nullptr) != 0) { error = std::string("setgroups failed: ") + std::strerror(errno); return false; }
            if (::setgid(static_cast<gid_t>(gid)) != 0) { error = std::string("setgid failed: ") + std::strerror(errno); return false; }
            if (::setuid(static_cast<uid_t>(uid)) != 0) { error = std::string("setuid failed: ") + std::strerror(errno); return false; }
            if (::getuid() != uid || ::geteuid() != uid || ::getgid() != gid || ::getegid() != gid) {
                error = "the user or group id is not the requested one after dropping privileges";
                return false;
            }
            // the way back must be closed
            if (::setuid(0) == 0 || ::seteuid(0) == 0 || ::setgid(0) == 0 || ::setegid(0) == 0) {
                error = "privileges could still be regained after dropping them";
                return false;
            }
            const int groups = ::getgroups(0, nullptr);
            if (groups > 1) {
                error = "supplementary groups remain after dropping privileges";
                return false;
            }
            if (groups == 1) {
                gid_t only = 0;
                if (::getgroups(1, &only) != 1 || only != static_cast<gid_t>(gid)) {
                    error = "a foreign supplementary group remains after dropping privileges";
                    return false;
                }
            }
#ifdef __linux__
            if (::prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) { error = "PR_SET_NO_NEW_PRIVS failed"; return false; }
            // the kernel ends the worker if the GUI dies; the check closes the race with a parent that is already gone
            if (::prctl(PR_SET_PDEATHSIG, SIGTERM) != 0) { error = "PR_SET_PDEATHSIG failed"; return false; }
            if (::getppid() != parentBefore) { error = "the parent process is gone"; return false; }
#else
            (void) parentBefore;
#endif
            return true;
        }

        class LibpcapSource : public PacketSource {
        public:
            explicit LibpcapSource(pcap_t *h) : h_(h) {}
            Status next(SourcePacket &out) override {
                pcap_pkthdr *header = nullptr;
                const u_char *bytes = nullptr;
                const int rc = pcap_next_ex(h_, &header, &bytes);
                if (rc == 1) {
                    out.tsSeconds = static_cast<uint64_t>(header->ts.tv_sec);
                    out.tsMicros = static_cast<uint32_t>(header->ts.tv_usec);
                    out.data = bytes;
                    out.capturedLength = header->caplen;
                    out.originalLength = header->len;
                    return Status::Packet;
                }
                if (rc == 0) return Status::Timeout;
                if (rc == PCAP_ERROR_BREAK || rc == -2) return Status::End;
                error_ = pcap_geterr(h_);
                return Status::Error;
            }
            std::string error() const override { return error_; }

        private:
            pcap_t *h_;
            std::string error_;
        };
    } // namespace

    int runCaptureWorker(const std::vector<std::string> &args) {
        const ParseResult parsed = parseWorkerArgs(args);
        if (!parsed.ok) return fail(kExitUsage, parsed.error);
        const WorkerArgs &a = parsed.args;

        const pid_t parentBefore = ::getppid();
        installSignals();
        clearEnvironment();
        ::umask(077);
        const rlimit noCore{0, 0};
        ::setrlimit(RLIMIT_CORE, &noCore);

        std::string error;
        // Not root: there is nothing to drop and the target must be this very user. Said before the device is touched.
        if (::geteuid() != 0 && ::getuid() != 0 && (::getuid() != a.uid || ::geteuid() != a.uid || ::getgid() != a.gid || ::getegid() != a.gid)) {
            return fail(kExitDropFailed, "not running as root, so --uid/--gid must be the current user's");
        }
        if (!interfaceExists(a.interfaceName, error)) return fail(kExitNoSuchInterface, error);

        // 1. open the device and set the filter: this is what needs the administrator rights
        char errbuf[PCAP_ERRBUF_SIZE] = {0};
        pcap_t *h = pcap_create(a.interfaceName.c_str(), errbuf);
        if (!h) return fail(kExitOpenFailed, std::string("cannot open ") + a.interfaceName + ": " + errbuf);
        pcap_set_snaplen(h, static_cast<int>(a.snaplen));
        pcap_set_promisc(h, a.promiscuous ? 1 : 0);
        pcap_set_timeout(h, 250);
        pcap_set_immediate_mode(h, 1);
        const int rc = pcap_activate(h);
        if (rc < 0) {
            const std::string detail = pcap_geterr(h);
            const std::string text = "cannot open " + a.interfaceName + ": " + (detail.empty() ? pcap_statustostr(rc) : detail);
            pcap_close(h);
            return fail(rc == PCAP_ERROR_PERM_DENIED ? kExitPermission : kExitOpenFailed, text);
        }
        if (!a.filter.empty()) {
            bpf_program program{};
            if (pcap_compile(h, &program, a.filter.c_str(), 1, PCAP_NETMASK_UNKNOWN) != 0) {
                const std::string text = std::string("invalid capture filter: ") + pcap_geterr(h);
                pcap_close(h);
                return fail(kExitFilter, text);
            }
            const int src = pcap_setfilter(h, &program);
            pcap_freecode(&program);
            if (src != 0) {
                const std::string text = std::string("cannot apply the capture filter: ") + pcap_geterr(h);
                pcap_close(h);
                return fail(kExitFilter, text);
            }
        }
        const uint32_t linkType = dltToLinkType(pcap_datalink(h));

        // 2. give the privileges up for good (no-op when not running as root)
        if (!dropPrivileges(a.uid, a.gid, parentBefore, error)) {
            pcap_close(h);
            return fail(kExitDropFailed, error);
        }

        // 3. only now, as the user, open the pipe
        const int fd = openFifoForWriting(a.fifoPath, a.uid, &g_stop, 10000, error);
        if (fd < 0) {
            pcap_close(h);
            return fail(kExitFifo, error);
        }

        // 4. stream until the GUI goes away
        LibpcapSource source(h);
        const StreamEnd end = streamCapture(fd, source, linkType, a.snaplen, &g_stop, error, true);
        ::close(fd);
        pcap_close(h);
        switch (end) {
            case StreamEnd::Stopped:
            case StreamEnd::ReaderGone:
            case StreamEnd::SourceEnded: return kExitOk;
            case StreamEnd::SourceError: return fail(kExitCapture, "capture stopped: " + error);
            case StreamEnd::WriteError: return fail(kExitFifo, error);
        }
        return kExitOk;
    }
#else
    int runCaptureWorker(const std::vector<std::string> &args) {
        const ParseResult parsed = parseWorkerArgs(args);
        if (!parsed.ok) return fail(kExitUsage, parsed.error);
        return fail(kExitUnsupported, "this build of ImShark has no live capture");
    }
#endif // IMSHARK_HAVE_LIVE_CAPTURE
#endif // _WIN32
} // namespace capture::worker
