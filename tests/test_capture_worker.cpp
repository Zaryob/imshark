// The capture worker without privileges and without a device: the strict argument parser, the argv the GUI builds for
// pkexec / osascript, the failure texts, the stream loop (against a scripted packet source and a real pipe / FIFO) and the
// private FIFO. Nothing in here starts pkexec or osascript.
#include <gtest/gtest.h>

#include <algorithm>
#include <chrono>
#include <csignal>
#include <filesystem>
#include <future>
#include <thread>

#ifndef _WIN32
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

#include <capture/capture_worker.h>
#include <capture/pcap_stream.h>
#include <capture/worker_launch.h>

#include "pcap_stream_support.h"
#include "support.h"

using namespace capture;
using capture::worker::parseWorkerArgs;

namespace {
    std::vector<std::string> validArgs() {
        return {"--interface", "en0", "--snaplen", "1500", "--promisc", "1", "--filter", "tcp port 443", "--uid", "501", "--gid", "20", "--fifo", "/tmp/x/capture.fifo"};
    }

    /// Replaces the value of `flag` in a valid argument list.
    std::vector<std::string> withValue(const std::string &flag, const std::string &value) {
        auto args = validArgs();
        for (size_t i = 0; i + 1 < args.size(); i += 2) {
            if (args[i] == flag) args[i + 1] = value;
        }
        return args;
    }

    /// Values that a shell (or anything that interprets text) would act on.
    const std::vector<std::string> &hostileValues() {
        static const std::vector<std::string> v = {
            "a b",
            "it's \"quoted\"",
            "$(touch /tmp/imshark_pwned)",
            "`touch /tmp/imshark_pwned`",
            "line1\nline2",
            "x; touch /tmp/imshark_pwned #",
            "${IFS}|&<>*?[]~",
            "back\\slash",
        };
        return v;
    }
} // namespace

// ---- argument parser -------------------------------------------------------------------------------------------------
TEST(CaptureWorkerArgs, AValidSetIsParsed) {
    const auto r = parseWorkerArgs(validArgs());
    ASSERT_TRUE(r.ok) << r.error;
    EXPECT_EQ(r.args.interfaceName, "en0");
    EXPECT_EQ(r.args.snaplen, 1500u);
    EXPECT_TRUE(r.args.promiscuous);
    EXPECT_EQ(r.args.filter, "tcp port 443");
    EXPECT_EQ(r.args.uid, 501u);
    EXPECT_EQ(r.args.gid, 20u);
    EXPECT_EQ(r.args.fifoPath, "/tmp/x/capture.fifo");
}

TEST(CaptureWorkerArgs, AnEmptyFilterAndTheSnaplenBoundsAreValid) {
    EXPECT_TRUE(parseWorkerArgs(withValue("--filter", "")).ok);
    EXPECT_TRUE(parseWorkerArgs(withValue("--snaplen", "64")).ok);
    EXPECT_TRUE(parseWorkerArgs(withValue("--snaplen", "262144")).ok);
    EXPECT_FALSE(parseWorkerArgs(withValue("--promisc", "0")).args.promiscuous);
}

TEST(CaptureWorkerArgs, EveryInvalidFormIsRefusedWithAOneLineMessage) {
    struct Case {
        const char *name;
        std::vector<std::string> args;
    };
    auto dup = validArgs();
    dup.insert(dup.end(), {"--snaplen", "100"});
    auto unknown = validArgs();
    unknown.insert(unknown.end(), {"--shell", "/bin/sh"});
    auto missingValue = validArgs();
    missingValue.pop_back();
    auto missingFlag = validArgs();
    missingFlag.resize(missingFlag.size() - 2);
    const std::vector<Case> cases = {
        {"empty", {}},
        {"duplicate flag", dup},
        {"unknown flag", unknown},
        {"missing value", missingValue},
        {"missing flag", missingFlag},
        {"positional argument", {"en0"}},
        {"flag=value form", {"--interface=en0"}},
        {"empty interface", withValue("--interface", "")},
        {"snaplen letters", withValue("--snaplen", "15a0")},
        {"snaplen empty", withValue("--snaplen", "")},
        {"snaplen negative", withValue("--snaplen", "-100")},
        {"snaplen plus", withValue("--snaplen", "+100")},
        {"snaplen space", withValue("--snaplen", " 100")},
        {"snaplen hex", withValue("--snaplen", "0x100")},
        {"snaplen too small", withValue("--snaplen", "63")},
        {"snaplen too large", withValue("--snaplen", "262145")},
        {"snaplen overflow", withValue("--snaplen", "99999999999999999999")},
        {"promisc 2", withValue("--promisc", "2")},
        {"promisc word", withValue("--promisc", "true")},
        {"uid zero", withValue("--uid", "0")},
        {"gid zero", withValue("--gid", "0")},
        {"uid negative", withValue("--uid", "-1")},
        {"uid all ones", withValue("--uid", "4294967295")},
        {"uid text", withValue("--uid", "root")},
        {"gid text", withValue("--gid", "staff")},
        {"relative fifo", withValue("--fifo", "capture.fifo")},
        {"empty fifo", withValue("--fifo", "")},
        {"interface too long", withValue("--interface", std::string(300, 'a'))},
    };
    for (const auto &c: cases) {
        const auto r = parseWorkerArgs(c.args);
        EXPECT_FALSE(r.ok) << c.name;
        EXPECT_FALSE(r.error.empty()) << c.name;
        EXPECT_EQ(r.error.find('\n'), std::string::npos) << c.name << ": " << r.error;
    }
}

TEST(CaptureWorkerArgs, QuotesSpacesSubstitutionsAndNewlinesAreTakenVerbatim) {
    for (const std::string &value: hostileValues()) {
        auto args = withValue("--interface", value);
        auto r = parseWorkerArgs(args);
        ASSERT_TRUE(r.ok) << value << ": " << r.error;
        EXPECT_EQ(r.args.interfaceName, value);

        r = parseWorkerArgs(withValue("--filter", value));
        ASSERT_TRUE(r.ok) << value << ": " << r.error;
        EXPECT_EQ(r.args.filter, value);

        r = parseWorkerArgs(withValue("--fifo", "/" + value));
        ASSERT_TRUE(r.ok) << value << ": " << r.error;
        EXPECT_EQ(r.args.fifoPath, "/" + value);
    }
    EXPECT_FALSE(std::filesystem::exists("/tmp/imshark_pwned")) << "a value was interpreted";
}

TEST(CaptureWorkerArgs, AValueThatLooksLikeAFlagIsStillAValue) {
    const auto r = parseWorkerArgs(withValue("--filter", "--uid"));
    ASSERT_TRUE(r.ok) << r.error;
    EXPECT_EQ(r.args.filter, "--uid");
    EXPECT_EQ(r.args.uid, 501u);
}

TEST(CaptureWorkerArgs, TheCommandLineIsTheExactInverseOfTheParser) {
    worker::WorkerArgs a;
    a.interfaceName = "it's \"x\" $(y)";
    a.snaplen = 262144;
    a.promiscuous = false;
    a.filter = "host 1.2.3.4 or `z`\nnext";
    a.uid = 1000;
    a.gid = 1001;
    a.fifoPath = "/tmp/a b/capture.fifo";
    const auto line = worker::workerCommandLine(a);
    ASSERT_EQ(line.size(), 15u);
    EXPECT_EQ(line[0], "--capture-worker");
    const auto r = parseWorkerArgs(std::vector<std::string>(line.begin() + 1, line.end()));
    ASSERT_TRUE(r.ok) << r.error;
    EXPECT_EQ(r.args.interfaceName, a.interfaceName);
    EXPECT_EQ(r.args.snaplen, a.snaplen);
    EXPECT_EQ(r.args.promiscuous, a.promiscuous);
    EXPECT_EQ(r.args.filter, a.filter);
    EXPECT_EQ(r.args.uid, a.uid);
    EXPECT_EQ(r.args.gid, a.gid);
    EXPECT_EQ(r.args.fifoPath, a.fifoPath);
}

// ---- launcher argv ------------------------------------------------------------------------------------------------------
namespace {
    worker::WorkerArgs hostileArgs() {
        worker::WorkerArgs a;
        a.interfaceName = "en0\"; touch /tmp/imshark_pwned; \"";
        a.snaplen = 1500;
        a.promiscuous = true;
        a.filter = "tcp and $(touch /tmp/imshark_pwned) and `id`\nand 'x'";
        a.uid = 501;
        a.gid = 20;
        a.fifoPath = "/tmp/dir with space/capture.fifo";
        return a;
    }
    const char *const kExe = "/Applications/Im Shark's \"app\"/imshark";
} // namespace

TEST(WorkerLaunch, PkexecGetsEveryValueAsItsOwnUnchangedElement) {
    const auto args = worker::workerCommandLine(hostileArgs());
    const auto argv = buildPkexecArgv(kExe, args);
    ASSERT_EQ(argv.size(), 2 + args.size());
    EXPECT_EQ(argv[0], kPkexecPath);
    EXPECT_EQ(argv[1], kExe);
    for (size_t i = 0; i < args.size(); ++i) EXPECT_EQ(argv[2 + i], args[i]) << i;
    EXPECT_EQ(argv[2], "--capture-worker");
}

TEST(WorkerLaunch, OsascriptGetsEveryValueAsItsOwnUnchangedElementAfterTheDoubleDash) {
    const auto args = worker::workerCommandLine(hostileArgs());
    const auto argv = buildOsascriptArgv(kExe, args);
    EXPECT_EQ(argv[0], kOsascriptPath);
    const auto dashes = std::find(argv.begin(), argv.end(), std::string("--"));
    ASSERT_NE(dashes, argv.end());
    const std::vector<std::string> tail(dashes + 1, argv.end());
    ASSERT_EQ(tail.size(), 1 + args.size());
    EXPECT_EQ(tail[0], kExe);
    for (size_t i = 0; i < args.size(); ++i) EXPECT_EQ(tail[1 + i], args[i]) << i;

    // before the "--": only "-e <fixed script line>" pairs
    const size_t head = static_cast<size_t>(dashes - argv.begin()) - 1;
    ASSERT_EQ(head, osascriptScript().size() * 2);
    for (size_t i = 0; i < osascriptScript().size(); ++i) {
        EXPECT_EQ(argv[1 + 2 * i], "-e");
        EXPECT_EQ(argv[2 + 2 * i], osascriptScript()[i]);
    }
}

TEST(WorkerLaunch, TheAppleScriptTemplateContainsNoUserValue) {
    std::string script;
    for (const auto &line: osascriptScript()) script += line + "\n";
    for (const auto &piece: worker::workerCommandLine(hostileArgs())) {
        if (piece.size() > 3) EXPECT_EQ(script.find(piece), std::string::npos) << piece;
    }
    EXPECT_EQ(script.find(kExe), std::string::npos);
    EXPECT_EQ(script.find("imshark"), std::string::npos);
    // every value reaches the shell through `quoted form of`, and only through it
    EXPECT_NE(script.find("quoted form of (item 1 of argv)"), std::string::npos);
    EXPECT_NE(script.find("quoted form of (item i of argv)"), std::string::npos);
    EXPECT_NE(script.find("do shell script cmd with administrator privileges"), std::string::npos);
    // the template is the same whatever the values are
    EXPECT_EQ(osascriptScript(), osascriptScript());
    const auto a = buildOsascriptArgv("/x/imshark", worker::workerCommandLine(worker::WorkerArgs{}));
    const auto b = buildOsascriptArgv(kExe, worker::workerCommandLine(hostileArgs()));
    EXPECT_TRUE(std::equal(a.begin(), a.begin() + 1 + 2 * static_cast<long>(osascriptScript().size()), b.begin()));
}

TEST(WorkerLaunch, ElevationArgvFollowsTheMethod) {
    const auto args = worker::workerCommandLine(hostileArgs());
    EXPECT_TRUE(buildElevationArgv(ElevationMethod::None, kExe, args).empty());
    EXPECT_EQ(buildElevationArgv(ElevationMethod::Pkexec, kExe, args), buildPkexecArgv(kExe, args));
    EXPECT_EQ(buildElevationArgv(ElevationMethod::Osascript, kExe, args), buildOsascriptArgv(kExe, args));
}

TEST(WorkerLaunch, FailureTextsAreSpecific) {
    ProcessExit e;
    e.exited = true;
    e.code = 126;
    EXPECT_NE(describeWorkerFailure(ElevationMethod::Pkexec, e, "").find("dismissed"), std::string::npos);
    e.code = 127;
    EXPECT_NE(describeWorkerFailure(ElevationMethod::Pkexec, e, "").find("authentication agent"), std::string::npos);
    e.code = 1;
    EXPECT_EQ(describeWorkerFailure(ElevationMethod::Osascript, e, "0:42: execution error: User canceled. (-128)"), "Authorization cancelled");
    EXPECT_NE(describeWorkerFailure(ElevationMethod::Osascript, e, "execution error: nope (1)").find("failed"), std::string::npos);
    // the worker's own message, also inside osascript's wrapper
    e.code = 5;
    EXPECT_EQ(describeWorkerFailure(ElevationMethod::Pkexec, e, "imshark-capture-worker: cannot open en0: boom\n"), "Capture helper: cannot open en0: boom");
    EXPECT_EQ(describeWorkerFailure(ElevationMethod::Osascript, e, "execution error: imshark-capture-worker: cannot open en0: boom (5)\n"),
              "Capture helper: cannot open en0: boom");
    e.code = 0;
    EXPECT_TRUE(describeWorkerFailure(ElevationMethod::Pkexec, e, "").empty());
    ProcessExit spawn;
    spawn.exited = spawn.spawnFailed = true;
    EXPECT_NE(describeWorkerFailure(ElevationMethod::Pkexec, spawn, "Cannot start /usr/bin/pkexec: No such file or directory").find("pkexec"), std::string::npos);
}

#ifndef _WIN32
namespace {
    /// A script: `packets` packets, then timeouts (or End / Error) forever.
    class ScriptedSource : public worker::PacketSource {
    public:
        enum class After { Timeouts, End, Error };
        ScriptedSource(size_t packets, After after, uint32_t frameLength = 60) : packets_(packets), after_(after), frame_(frameLength, 0xab) {}
        Status next(worker::SourcePacket &out) override {
            if (sent_ < packets_) {
                out.tsSeconds = 1000 + sent_;
                out.tsMicros = static_cast<uint32_t>(sent_);
                out.data = frame_.data();
                out.capturedLength = static_cast<uint32_t>(frame_.size());
                out.originalLength = static_cast<uint32_t>(frame_.size()) + 40;
                ++sent_;
                return Status::Packet;
            }
            switch (after_) {
                case After::End: return Status::End;
                case After::Error: return Status::Error;
                case After::Timeouts: break;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
            return Status::Timeout;
        }
        std::string error() const override { return "device vanished"; }
        size_t sent() const { return sent_; }

    private:
        size_t packets_, sent_ = 0;
        After after_;
        std::vector<unsigned char> frame_;
    };

    struct Pipe {
        int r = -1, w = -1;
        Pipe() {
            int fds[2];
            if (::pipe(fds) == 0) {
                r = fds[0];
                w = fds[1];
            }
        }
        ~Pipe() {
            if (r >= 0) ::close(r);
            if (w >= 0) ::close(w);
        }
        void closeRead() { ::close(r); r = -1; }
        Pipe(const Pipe &) = delete;
        Pipe &operator=(const Pipe &) = delete;
    };

    std::string readAll(int fd) {
        std::string out;
        char buf[4096];
        ssize_t n;
        while ((n = ::read(fd, buf, sizeof buf)) > 0) out.append(buf, static_cast<size_t>(n));
        return out;
    }

    class WorkerStream : public ::testing::Test {
    protected:
        void SetUp() override { std::signal(SIGPIPE, SIG_IGN); }   // what the worker does: a closed reader is EPIPE
    };
} // namespace

TEST_F(WorkerStream, TheWriterSendsAValidPcapStreamWithTheRealLinkTypeAndSnaplen) {
    Pipe p;
    ScriptedSource source(3, ScriptedSource::After::End, 200);
    std::string error;
    const auto end = worker::streamCapture(p.w, source, 113, 100, nullptr, error);   // snaplen 100 truncates the 200 byte frames
    EXPECT_EQ(end, worker::StreamEnd::SourceEnded);
    ::close(p.w);
    p.w = -1;
    const std::string bytes = readAll(p.r);

    struct Record { uint64_t sec; uint32_t usec, caplen, origlen; };
    std::vector<Record> seen;
    PcapStreamHeader header;
    PcapStreamParser parser([&](const PcapStreamHeader &h) { header = h; return true; },
                            [&](uint64_t s, uint32_t us, const char *, uint32_t cap, uint32_t orig) { seen.push_back({s, us, cap, orig}); });
    ASSERT_TRUE(parser.feed(bytes.data(), bytes.size())) << parser.error();
    ASSERT_TRUE(parser.finish()) << parser.error();
    EXPECT_EQ(header.linkType, 113u);
    EXPECT_EQ(header.snaplen, 100u);
    EXPECT_FALSE(header.bigEndian);
    EXPECT_FALSE(header.nanosecond);
    ASSERT_EQ(seen.size(), 3u);
    EXPECT_EQ(seen[1].sec, 1001u);
    EXPECT_EQ(seen[1].usec, 1u);
    EXPECT_EQ(seen[1].caplen, 100u) << "never more than the snaplen";
    EXPECT_EQ(seen[1].origlen, 240u);
}

TEST_F(WorkerStream, AClosedReaderEndsTheWriterPromptlyEvenWithoutTraffic) {
    Pipe p;
    ScriptedSource source(0, ScriptedSource::After::Timeouts);
    std::string error;
    auto result = std::async(std::launch::async, [&] { return worker::streamCapture(p.w, source, 1, 65535, nullptr, error); });
    // wait until the header went through, then the GUI "closes the window"
    char header[24];
    size_t got = 0;
    while (got < sizeof header) {
        const ssize_t n = ::read(p.r, header + got, sizeof header - got);
        ASSERT_GT(n, 0);
        got += static_cast<size_t>(n);
    }
    p.closeRead();
    const auto t0 = std::chrono::steady_clock::now();
    ASSERT_EQ(result.wait_for(std::chrono::seconds(5)), std::future_status::ready) << "the writer kept running without a reader";
    EXPECT_EQ(result.get(), worker::StreamEnd::ReaderGone);
    EXPECT_LT(std::chrono::steady_clock::now() - t0, std::chrono::seconds(2));
}

TEST_F(WorkerStream, AClosedReaderEndsTheWriterAtTheNextPacket) {
    Pipe p;
    p.closeRead();
    ScriptedSource source(1000, ScriptedSource::After::Timeouts);
    std::string error;
    EXPECT_EQ(worker::streamCapture(p.w, source, 1, 65535, nullptr, error), worker::StreamEnd::ReaderGone);   // EPIPE on the header
    EXPECT_EQ(source.sent(), 0u);
}

TEST_F(WorkerStream, TheStopFlagEndsTheWriter) {
    Pipe p;
    volatile std::sig_atomic_t stop = 0;
    ScriptedSource source(0, ScriptedSource::After::Timeouts);
    std::string error;
    auto result = std::async(std::launch::async, [&] { return worker::streamCapture(p.w, source, 1, 65535, &stop, error); });
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    stop = 1;
    ASSERT_EQ(result.wait_for(std::chrono::seconds(5)), std::future_status::ready);
    EXPECT_EQ(result.get(), worker::StreamEnd::Stopped);
}

TEST_F(WorkerStream, ASourceErrorIsReported) {
    Pipe p;
    ScriptedSource source(1, ScriptedSource::After::Error);
    std::string error;
    EXPECT_EQ(worker::streamCapture(p.w, source, 1, 65535, nullptr, error), worker::StreamEnd::SourceError);
    EXPECT_EQ(error, "device vanished");
}

// ---- private FIFO -----------------------------------------------------------------------------------------------------
TEST(PrivateFifoTest, DirectoryIs0700AndFifoIs0600OwnedByTheUserAndBothAreRemoved) {
    std::string dir, path;
    {
        PrivateFifo fifo;
        std::string error;
        ASSERT_TRUE(fifo.create(error)) << error;
        dir = fifo.directory();
        path = fifo.path();
        struct stat st {};
        ASSERT_EQ(::lstat(dir.c_str(), &st), 0);
        EXPECT_TRUE(S_ISDIR(st.st_mode));
        EXPECT_EQ(st.st_mode & 0777, 0700u);
        EXPECT_EQ(st.st_uid, ::geteuid());
        ASSERT_EQ(::lstat(path.c_str(), &st), 0);
        EXPECT_TRUE(S_ISFIFO(st.st_mode));
        EXPECT_EQ(st.st_mode & 0777, 0600u);
        EXPECT_EQ(st.st_uid, ::geteuid());
        EXPECT_EQ(std::filesystem::path(path).parent_path().string(), dir);
        EXPECT_EQ(std::filesystem::path(path).filename().string(), "capture.fifo");
    }
    EXPECT_FALSE(std::filesystem::exists(path)) << "the destructor removes the FIFO";
    EXPECT_FALSE(std::filesystem::exists(dir)) << "... and its directory";
}

TEST(PrivateFifoTest, RemoveIsIdempotentAndEveryCreateMakesANewDirectory) {
    PrivateFifo fifo;
    std::string error;
    ASSERT_TRUE(fifo.create(error));
    const std::string first = fifo.directory();
    ASSERT_TRUE(fifo.create(error)) << "create() removes the previous one first";
    EXPECT_NE(fifo.directory(), first);
    EXPECT_FALSE(std::filesystem::exists(first));
    fifo.remove();
    fifo.remove();
    EXPECT_TRUE(fifo.path().empty());
}

TEST(PrivateFifoTest, OpeningForWritingChecksTypeOwnerAndSymlinks) {
    PrivateFifo fifo;
    std::string error;
    ASSERT_TRUE(fifo.create(error)) << error;
    const volatile std::sig_atomic_t *noStop = nullptr;

    // nobody reads yet: no hang, a clear failure
    EXPECT_EQ(worker::openFifoForWriting(fifo.path(), ::geteuid(), noStop, 100, error), -1);
    EXPECT_FALSE(error.empty());

    const int reader = ::open(fifo.path().c_str(), O_RDONLY | O_NONBLOCK | O_CLOEXEC);
    ASSERT_GE(reader, 0);
    const int fd = worker::openFifoForWriting(fifo.path(), ::geteuid(), noStop, 1000, error);
    EXPECT_GE(fd, 0) << error;
    if (fd >= 0) {
        EXPECT_EQ(::fcntl(fd, F_GETFL) & O_NONBLOCK, 0) << "writes block again";
        ::close(fd);
    }

    // not owned by the expected user
    EXPECT_EQ(worker::openFifoForWriting(fifo.path(), ::geteuid() + 1, noStop, 1000, error), -1);
    EXPECT_NE(error.find("owned"), std::string::npos) << error;

    // a symlink to the FIFO is refused (O_NOFOLLOW)
    const std::string link = fifo.directory() + "/link";
    ASSERT_EQ(::symlink(fifo.path().c_str(), link.c_str()), 0);
    EXPECT_EQ(worker::openFifoForWriting(link, ::geteuid(), noStop, 1000, error), -1);
    ::unlink(link.c_str());

    // a regular file is refused
    const std::string regular = fifo.directory() + "/regular";
    {
        const int f = ::open(regular.c_str(), O_CREAT | O_WRONLY, 0600);
        ASSERT_GE(f, 0);
        ::close(f);
    }
    EXPECT_EQ(worker::openFifoForWriting(regular, ::geteuid(), noStop, 1000, error), -1);
    EXPECT_NE(error.find("FIFO"), std::string::npos) << error;
    ::unlink(regular.c_str());
    ::close(reader);
}

TEST_F(WorkerStream, AnUnlinkedFifoEndsTheWriter) {
    PrivateFifo fifo;
    std::string error;
    ASSERT_TRUE(fifo.create(error)) << error;
    const int reader = ::open(fifo.path().c_str(), O_RDONLY | O_NONBLOCK | O_CLOEXEC);
    ASSERT_GE(reader, 0);
    const int fd = worker::openFifoForWriting(fifo.path(), ::geteuid(), nullptr, 1000, error);
    ASSERT_GE(fd, 0) << error;
    ScriptedSource source(0, ScriptedSource::After::Timeouts);
    auto result = std::async(std::launch::async, [&] { return worker::streamCapture(fd, source, 1, 65535, nullptr, error, true); });
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    fifo.remove();      // what the GUI does when the capture ends (macOS cannot see an idle FIFO's reader leave through poll)
    ASSERT_EQ(result.wait_for(std::chrono::seconds(5)), std::future_status::ready);
    EXPECT_EQ(result.get(), worker::StreamEnd::ReaderGone);
    ::close(fd);
    ::close(reader);
}
#endif
