// The reading side of the capture worker: the pcap stream parser and LiveCapture's worker stream backend, fed with
// synthetic (good and hostile) streams through real pipes, and the elevated session with a fake process starter, so
// that no test ever asks for an authorization. POSIX only (pipes, FIFOs, /bin/sh).
#include <gtest/gtest.h>

#ifndef _WIN32
#include <algorithm>
#include <chrono>
#include <csignal>
#include <filesystem>
#include <fstream>
#include <random>
#include <sstream>
#include <thread>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <capture/live_capture.h>
#include <capture/pcap_stream.h>
#include <capture/worker_launch.h>

#include "pcap_stream_support.h"
#include "support.h"

using namespace capture;
namespace ps = pcapstream;

namespace {
    class StreamReader : public ::testing::Test {
    protected:
        void SetUp() override { std::signal(SIGPIPE, SIG_IGN); }
    };

    bool waitUntil(const std::function<bool()> &done, int ms = 5000) {
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(ms);
        while (!done()) {
            if (std::chrono::steady_clock::now() > deadline) return false;
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        }
        return true;
    }

    struct Outcome {
        bool ended = false;
        bool streaming = false;
        std::string error;
        uint64_t packets = 0;
        uint32_t linkType = 0, snaplen = 0;
        std::vector<CapturedPacket> records;
        std::string tempFile;       // contents of the temp pcap
    };

    /// Pushes `bytes` through a real pipe into LiveCapture::startFromWorkerStream (written in `chunk` byte pieces by a
    /// thread, so the reader sees partial headers / records), waits until the session ended and collects the result.
    Outcome run(const std::string &bytes, size_t chunk = 0, int connectTimeoutMs = 400) {
        int fds[2];
        EXPECT_EQ(::pipe(fds), 0);
        std::thread writer([&] {
            size_t pos = 0;
            while (pos < bytes.size()) {
                const size_t n = std::min(chunk ? chunk : bytes.size(), bytes.size() - pos);
                const ssize_t w = ::write(fds[1], bytes.data() + pos, n);
                if (w <= 0) break;     // the reader refused the stream and closed its end
                pos += static_cast<size_t>(w);
            }
            ::close(fds[1]);
        });
        LiveCapture live;
        WorkerStreamOptions options;
        options.connectTimeoutMs = connectTimeoutMs;
        Outcome out;
        EXPECT_TRUE(live.startFromWorkerStream(fds[0], options));
        out.ended = waitUntil([&] { return !live.running(); });
        writer.join();
        live.stop();
        out.streaming = live.streaming();
        out.error = live.lastError();
        out.packets = live.packetCount();
        out.linkType = live.linkType();
        out.snaplen = live.snaplen();
        live.takePackets(out.records);
        std::ifstream f(core::pathFromUtf8(live.tempPath()), std::ios::binary);
        std::ostringstream ss;
        ss << f.rdbuf();
        out.tempFile = ss.str();
        return out;
    }

    std::string frame(size_t n, char c) { return std::string(n, c); }
} // namespace

// ---- good streams -----------------------------------------------------------------------------------------------------
TEST_F(StreamReader, AGoodStreamEndsUpInTheTempFileWithCorrectOffsetsAndTimestamps) {
    ps::Options o;
    o.linkType = 113;
    o.snaplen = 1000;
    const std::string a = frame(60, 'a'), b = frame(100, 'b'), c = frame(1, 'c');
    const std::string stream = ps::header(o) + ps::packet(o, 1700000000, 123456, a, 90) + ps::packet(o, 1700000001, 999999, b) + ps::packet(o, 1700000002, 0, c);
    const Outcome r = run(stream);
    ASSERT_TRUE(r.ended);
    EXPECT_TRUE(r.error.empty()) << r.error;
    EXPECT_TRUE(r.streaming);
    EXPECT_EQ(r.packets, 3u);
    EXPECT_EQ(r.linkType, 113u);
    EXPECT_EQ(r.snaplen, 1000u);
    ASSERT_EQ(r.records.size(), 3u);
    EXPECT_EQ(r.records[0].fileOffset, 24u + 16u);
    EXPECT_EQ(r.records[0].capturedLength, 60u);
    EXPECT_EQ(r.records[0].originalLength, 90u);
    EXPECT_EQ(r.records[0].tsSeconds, 1700000000u);
    EXPECT_EQ(r.records[0].tsMicros, 123456u);
    EXPECT_EQ(r.records[1].fileOffset, 24u + 16u + 60u + 16u);
    EXPECT_EQ(r.records[1].tsMicros, 999999u);
    EXPECT_EQ(r.records[2].fileOffset, 24u + 16u + 60u + 16u + 100u + 16u);
    EXPECT_EQ(r.records[2].linkType, 113u);
    // the bytes at those offsets are the frames
    ASSERT_GE(r.tempFile.size(), r.records[2].fileOffset + 1);
    EXPECT_EQ(r.tempFile.substr(r.records[0].fileOffset, 60), a);
    EXPECT_EQ(r.tempFile.substr(r.records[1].fileOffset, 100), b);
    EXPECT_EQ(r.tempFile.substr(r.records[2].fileOffset, 1), c);
}

TEST_F(StreamReader, ByteSwappedAndNanosecondVariantsAreAccepted) {
    for (const bool big: {false, true}) {
        for (const bool nano: {false, true}) {
            ps::Options o;
            o.bigEndian = big;
            o.nano = nano;
            o.snaplen = 500;
            const std::string stream = ps::header(o) + ps::packet(o, 42, nano ? 123456789u : 123456u, frame(30, 'z'));
            const Outcome r = run(stream);
            const std::string name = std::string(big ? "big endian " : "little endian ") + (nano ? "nano" : "micro");
            ASSERT_TRUE(r.ended) << name;
            EXPECT_TRUE(r.error.empty()) << name << ": " << r.error;
            ASSERT_EQ(r.records.size(), 1u) << name;
            EXPECT_EQ(r.records[0].tsSeconds, 42u) << name;
            EXPECT_EQ(r.records[0].tsMicros, 123456u) << name << ": nanoseconds become microseconds";
            EXPECT_EQ(r.records[0].capturedLength, 30u) << name;
            EXPECT_EQ(r.snaplen, 500u) << name;
        }
    }
}

TEST_F(StreamReader, AStreamDeliveredOneByteAtATimeWorks) {
    ps::Options o;
    const std::string stream = ps::header(o) + ps::packet(o, 7, 8, frame(20, 'q')) + ps::packet(o, 9, 10, frame(5, 'r'));
    const Outcome r = run(stream, 1);
    ASSERT_TRUE(r.ended);
    EXPECT_TRUE(r.error.empty()) << r.error;
    EXPECT_EQ(r.records.size(), 2u);
}

TEST_F(StreamReader, ARecordOfExactlyTheSnaplenAndAnEmptyRecordAreValid) {
    ps::Options o;
    o.snaplen = 262144;
    const std::string stream = ps::header(o) + ps::packet(o, 1, 1, frame(262144, 'm')) + ps::packet(o, 2, 2, "");
    const Outcome r = run(stream);
    ASSERT_TRUE(r.ended);
    EXPECT_TRUE(r.error.empty()) << r.error;
    ASSERT_EQ(r.records.size(), 2u);
    EXPECT_EQ(r.records[0].capturedLength, 262144u);
    EXPECT_EQ(r.records[1].capturedLength, 0u);
}

// ---- hostile streams ----------------------------------------------------------------------------------------------------
TEST_F(StreamReader, WrongMagicIsRefused) {
    ps::Options o;
    std::string stream = ps::header(o);
    stream[0] = 'X';
    stream += ps::packet(o, 1, 1, frame(10, 'a'));
    const Outcome r = run(stream);
    ASSERT_TRUE(r.ended);
    EXPECT_NE(r.error.find("not a pcap stream"), std::string::npos) << r.error;
    EXPECT_EQ(r.packets, 0u);
    EXPECT_FALSE(r.streaming);
}

TEST_F(StreamReader, TruncatedHeaderIsAnErrorNotACrash) {
    const std::string stream = ps::header().substr(0, 11);
    const Outcome r = run(stream);
    ASSERT_TRUE(r.ended);
    EXPECT_NE(r.error.find("ended inside the pcap header"), std::string::npos) << r.error;
    EXPECT_EQ(r.packets, 0u);
}

TEST_F(StreamReader, NoDataAtAllIsAnError) {
    const Outcome r = run("", 0, 200);
    ASSERT_TRUE(r.ended);
    EXPECT_FALSE(r.error.empty());
    EXPECT_FALSE(r.streaming);
}

TEST_F(StreamReader, NonsenseHeaderFieldsAreRefused) {
    {
        ps::Options o;
        o.versionMajor = 3;
        EXPECT_NE(run(ps::header(o)).error.find("version"), std::string::npos);
    }
    for (const uint32_t snaplen: {0u, 262145u, 0xffffffffu}) {
        ps::Options o;
        o.snaplen = snaplen;
        const Outcome r = run(ps::header(o));
        EXPECT_NE(r.error.find("snapshot length"), std::string::npos) << snaplen << ": " << r.error;
        EXPECT_FALSE(r.streaming);
    }
    {
        ps::Options o;
        o.linkType = 0x7fffffff;
        EXPECT_NE(run(ps::header(o)).error.find("link type"), std::string::npos);
    }
}

TEST_F(StreamReader, ARecordLongerThanTheSnaplenIsRefusedAndEarlierPacketsStay) {
    ps::Options o;
    o.snaplen = 100;
    const std::string stream = ps::header(o) + ps::packet(o, 1, 1, frame(50, 'a')) + ps::record(o, 2, 2, 101, 101);
    const Outcome r = run(stream);
    ASSERT_TRUE(r.ended);
    EXPECT_NE(r.error.find("longer than the snapshot length"), std::string::npos) << r.error;
    EXPECT_EQ(r.packets, 1u);
    EXPECT_EQ(r.records.size(), 1u);
}

TEST_F(StreamReader, AHugeLengthIsRefusedWithoutAllocatingIt) {
    ps::Options o;
    o.snaplen = 262144;
    for (const uint32_t len: {262145u, 0x7fffffffu, 0xffffffffu}) {
        const std::string stream = ps::header(o) + ps::record(o, 1, 1, len, len, 16);
        const Outcome r = run(stream);
        ASSERT_TRUE(r.ended) << len;
        EXPECT_FALSE(r.error.empty()) << len;
        EXPECT_EQ(r.packets, 0u) << len;
    }
}

TEST_F(StreamReader, AnInvalidTimestampFractionIsRefused) {
    ps::Options micro;
    EXPECT_NE(run(ps::header(micro) + ps::record(micro, 1, 1000000, 4, 4)).error.find("timestamp"), std::string::npos);
    ps::Options nano;
    nano.nano = true;
    EXPECT_NE(run(ps::header(nano) + ps::record(nano, 1, 1000000000, 4, 4)).error.find("timestamp"), std::string::npos);
}

TEST_F(StreamReader, EarlyEofInsideARecordKeepsTheEarlierPacketsAndReportsAnError) {
    ps::Options o;
    const std::string stream = ps::header(o) + ps::packet(o, 1, 1, frame(40, 'a')) + ps::record(o, 2, 2, 100, 100, 30);   // body cut short
    const Outcome r = run(stream);
    ASSERT_TRUE(r.ended);
    EXPECT_NE(r.error.find("ended inside a packet record"), std::string::npos) << r.error;
    EXPECT_EQ(r.packets, 1u);
    // ... and inside the record header
    const Outcome r2 = run(ps::header(o) + ps::packet(o, 1, 1, frame(40, 'a')) + ps::record(o, 2, 2, 100, 100, 0).substr(0, 7));
    EXPECT_NE(r2.error.find("ended inside a packet record"), std::string::npos) << r2.error;
    EXPECT_EQ(r2.packets, 1u);
}

TEST(PcapStreamParserTest, RandomGarbageAndMutatedStreamsNeverCrash) {
    std::mt19937 rng(12345);
    ps::Options o;
    o.snaplen = 200;
    const std::string good = ps::header(o) + ps::packet(o, 1, 2, frame(50, 'a')) + ps::packet(o, 3, 4, frame(150, 'b'));
    for (int round = 0; round < 400; ++round) {
        std::string data = good;
        if (round % 2 == 0) {
            data.assign(static_cast<size_t>(rng() % 300), 0);
            for (char &c: data) c = static_cast<char>(rng());
        } else {
            for (int k = 0; k < 4; ++k) data[rng() % data.size()] = static_cast<char>(rng());
        }
        uint64_t seen = 0;
        PcapStreamParser parser(nullptr, [&](uint64_t, uint32_t, const char *, uint32_t cap, uint32_t) {
            ++seen;
            EXPECT_LE(cap, 262144u);
        });
        const size_t cut = rng() % (data.size() + 1);
        parser.feed(data.data(), cut);
        parser.feed(data.data() + cut, data.size() - cut);
        parser.finish();
        EXPECT_EQ(seen, parser.recordCount());
    }
}

// ---- the elevated session with a fake process starter -----------------------------------------------------------------
namespace {
    std::string optionValue(const std::vector<std::string> &argv, const std::string &flag) {
        for (size_t i = 0; i + 1 < argv.size(); ++i) {
            if (argv[i] == flag) return argv[i + 1];
        }
        return {};
    }

    /// Plays the worker: `script` runs under /bin/sh with the FIFO path as $1 (never with a value spliced into the script).
    WorkerProcess::Spawner shellSpawner(const std::string &script, std::vector<std::string> *seen = nullptr, const std::string &extra = {}) {
        return [=](const std::vector<std::string> &argv) {
            if (seen) *seen = argv;
            std::vector<std::string> run = {"/bin/sh", "-c", script, "sh", optionValue(argv, "--fifo")};
            if (!extra.empty()) run.push_back(extra);
            return spawnProcess(run);
        };
    }

    class Elevated : public ::testing::Test {
    protected:
        void SetUp() override {
            std::signal(SIGPIPE, SIG_IGN);
            if (!liveCaptureAvailable() || platformElevationMethod() == ElevationMethod::None) GTEST_SKIP() << "no helper capture in this build / platform";
        }
        static CaptureOptions options() {
            CaptureOptions o;
            o.interfaceName = "fake0";
            o.filter = "tcp and \"$(touch /tmp/imshark_pwned)\" `id`";
            o.snaplen = 1500;
            o.promiscuous = false;
            return o;
        }
        std::string pcapFile() {
            ps::Options o;
            o.snaplen = 1500;
            const std::string path = support::tempPath("elevated_stream.pcap");
            std::ofstream f(path, std::ios::binary);
            const std::string bytes = ps::header(o) + ps::packet(o, 100, 5, frame(60, 'a')) + ps::packet(o, 101, 6, frame(80, 'b'));
            f.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
            return path;
        }
    };
}

TEST_F(Elevated, TheWorkerStreamArrivesThroughThePrivateFifoAndEverythingIsRemovedAtTheEnd) {
    const std::string pcap = pcapFile();
    std::vector<std::string> argv;
    LiveCapture live;
    ASSERT_TRUE(live.startElevated(options(), shellSpawner("cat \"$2\" > \"$1\"", &argv, pcap))) << live.lastError();
    EXPECT_TRUE(live.authorizing() || live.streaming());

    // the private directory exists while the session lives
    const std::string fifo = live.workerFifoPath();
    ASSERT_FALSE(fifo.empty());
    struct stat st {};
    if (live.running()) {
        ASSERT_EQ(::stat(std::filesystem::path(fifo).parent_path().c_str(), &st), 0);
        EXPECT_EQ(st.st_mode & 0777, 0700u);
        EXPECT_EQ(st.st_uid, ::geteuid());
    }
    ASSERT_TRUE(waitUntil([&] { return !live.running(); })) << live.lastError();
    EXPECT_TRUE(live.lastError().empty()) << live.lastError();
    EXPECT_TRUE(live.streaming());
    std::vector<CapturedPacket> packets;
    EXPECT_EQ(live.takePackets(packets), 2u);
    ASSERT_EQ(packets.size(), 2u);
    EXPECT_EQ(packets[1].tsSeconds, 101u);
    EXPECT_FALSE(std::filesystem::exists(std::filesystem::path(fifo).parent_path())) << "the session is over: no FIFO, no directory";

    // what the starter was asked to run
    ASSERT_GE(argv.size(), 5u);
    EXPECT_EQ(argv[0], platformElevationMethod() == ElevationMethod::Pkexec ? kPkexecPath : kOsascriptPath);
    EXPECT_NE(std::find(argv.begin(), argv.end(), options().filter), argv.end()) << "the filter is one unchanged argv element";
    EXPECT_NE(std::find(argv.begin(), argv.end(), std::string("--capture-worker")), argv.end());
    EXPECT_EQ(optionValue(argv, "--interface"), "fake0");
    EXPECT_EQ(optionValue(argv, "--uid"), std::to_string(::getuid()));
    EXPECT_EQ(optionValue(argv, "--gid"), std::to_string(::getgid()));
    EXPECT_FALSE(std::filesystem::exists("/tmp/imshark_pwned"));
    std::filesystem::remove(pcap);
}

TEST_F(Elevated, AFailingWorkerEndsTheSessionWithItsMessageAndCleansUp) {
    LiveCapture live;
    ASSERT_TRUE(live.startElevated(options(), shellSpawner("echo 'imshark-capture-worker: cannot open fake0: boom' >&2; exit 5")));
    const std::string fifo = live.workerFifoPath();
    ASSERT_TRUE(waitUntil([&] { return !live.running(); }));
    EXPECT_NE(live.lastError().find("boom"), std::string::npos) << live.lastError();
    EXPECT_FALSE(live.streaming());
    EXPECT_FALSE(std::filesystem::exists(std::filesystem::path(fifo).parent_path())) << "removed also after a failure";
}

TEST_F(Elevated, ACancelledAuthorizationIsReportedAsSuch) {
    LiveCapture live;
    const bool pkexec = platformElevationMethod() == ElevationMethod::Pkexec;
    // pkexec: exit status 126 (dismissed); osascript: error -128 on stderr
    ASSERT_TRUE(live.startElevated(options(), shellSpawner(pkexec ? "exit 126" : "echo '0:90: execution error: User canceled. (-128)' >&2; exit 1")));
    ASSERT_TRUE(waitUntil([&] { return !live.running(); }));
    if (pkexec) EXPECT_NE(live.lastError().find("dismissed"), std::string::npos) << live.lastError();
    else EXPECT_EQ(live.lastError(), "Authorization cancelled");
}

TEST_F(Elevated, AProcessThatCannotBeStartedIsReported) {
    LiveCapture live;
    const auto failing = [](const std::vector<std::string> &) {
        SpawnResult r;
        r.error = "Cannot start /usr/bin/pkexec: No such file or directory";
        return r;
    };
    ASSERT_TRUE(live.startElevated(options(), failing));
    ASSERT_TRUE(waitUntil([&] { return !live.running(); }));
    EXPECT_NE(live.lastError().find("No such file"), std::string::npos) << live.lastError();
}

TEST_F(Elevated, StoppingWhileWaitingForTheAuthorizationReturnsAtOnceAndRemovesTheFifo) {
    LiveCapture live;
    ASSERT_TRUE(live.startElevated(options(), shellSpawner("exec sleep 30")));
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    EXPECT_TRUE(live.authorizing());
    EXPECT_TRUE(live.running());
    const std::string dir = std::filesystem::path(live.workerFifoPath()).parent_path().string();
    ASSERT_TRUE(std::filesystem::exists(dir));
    const auto t0 = std::chrono::steady_clock::now();
    live.stop();
    EXPECT_LT(std::chrono::steady_clock::now() - t0, std::chrono::seconds(2)) << "Cancel must not block the UI";
    EXPECT_FALSE(live.running());
    EXPECT_FALSE(std::filesystem::exists(dir));
    EXPECT_TRUE(live.workerFifoPath().empty());
}

TEST_F(Elevated, TheDestructorRemovesTheFifoToo) {
    std::string dir;
    {
        LiveCapture live;
        ASSERT_TRUE(live.startElevated(options(), shellSpawner("exec sleep 30")));
        dir = std::filesystem::path(live.workerFifoPath()).parent_path().string();
        ASSERT_TRUE(std::filesystem::exists(dir));
    }
    EXPECT_FALSE(std::filesystem::exists(dir));
}

TEST_F(Elevated, InvalidOptionsAreRefusedBeforeAnythingIsCreated) {
    LiveCapture live;
    CaptureOptions o = options();
    o.snaplen = 10;
    int calls = 0;
    const auto counting = [&](const std::vector<std::string> &) { ++calls; return SpawnResult(); };
    EXPECT_FALSE(live.startElevated(o, counting));
    EXPECT_FALSE(live.lastError().empty());
    o = options();
    o.interfaceName.clear();
    EXPECT_FALSE(live.startElevated(o, counting));
    EXPECT_EQ(calls, 0);
    EXPECT_TRUE(live.workerFifoPath().empty());
}
#else
TEST(WorkerStreamWindows, NotAvailableOnThisPlatform) { SUCCEED(); }
#endif
