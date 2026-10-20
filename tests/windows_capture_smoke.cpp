// Native Windows IPC regressions. No driver, administrator token or interactive UAC prompt is needed.
#define WIN32_LEAN_AND_MEAN
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <capture/live_capture.h>
#include <capture/worker_launch.h>
#include <capture/capture_worker.h>
#include <core.h>
#include <temp_file.h>
#include "pcap_stream_support.h"
#include <chrono>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <thread>

using namespace capture;
using namespace std::chrono_literals;
namespace ps = pcapstream;

namespace {
    void require(bool ok, const std::string &message) { if (!ok) throw std::runtime_error(message); }
    template<class F> bool waitUntil(F predicate, int ms = 3000) {
        const auto end = std::chrono::steady_clock::now() + std::chrono::milliseconds(ms);
        do { if (predicate()) return true; std::this_thread::sleep_for(5ms); } while (std::chrono::steady_clock::now() < end);
        return predicate();
    }
    auto makePipe() {
        auto pipe = std::make_unique<PrivateNamedPipe>();
        std::string error;
        require(pipe->create(error), error);
        return pipe;
    }
    HANDLE connect(const std::string &path) {
        std::string error;
        HANDLE h = static_cast<HANDLE>(worker::openPipeForWriting(path, nullptr, 2000, error));
        require(h != INVALID_HANDLE_VALUE, error);
        return h;
    }
    bool writeBytes(HANDLE h, const std::string &bytes, size_t chunk = 0) {
        size_t offset = 0;
        while (offset < bytes.size()) {
            DWORD n = 0;
            const DWORD count = static_cast<DWORD>(std::min(bytes.size() - offset, chunk ? chunk : bytes.size()));
            if (!WriteFile(h, bytes.data() + offset, count, &n, nullptr) || n == 0) return false;
            offset += n;
        }
        return true;
    }
    std::string readFile(const std::string &path) {
        std::ifstream in(core::pathFromUtf8(path), std::ios::binary);
        return {std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
    }
    void streamCase(const std::string &bytes, size_t expectedPackets, const std::string &expectedError = {}, size_t chunk = 0) {
        LiveCapture live;
        auto pipe = makePipe();
        const auto path = pipe->path();
        require(live.startFromWorkerPipe(std::move(pipe)), live.lastError());
        HANDLE writer = connect(path);
        std::jthread producer([&] { writeBytes(writer, bytes, chunk); FlushFileBuffers(writer); CloseHandle(writer); });
        const bool ended = waitUntil([&] { return !live.running(); });
        live.stop();
        require(ended, "reader did not end on EOF");
        require(live.packetCount() == expectedPackets, "packet count: " + std::to_string(live.packetCount()) + "; " + live.lastError());
        if (expectedError.empty()) require(live.lastError().empty(), live.lastError());
        else require(live.lastError().find(expectedError) != std::string::npos, "unexpected error: " + live.lastError());
        require(live.workerFifoPath().empty(), "pipe not cleaned up");
        if (expectedPackets && expectedError.empty()) require(readFile(live.tempPath()) == bytes, "saved pcap differs from worker stream");
    }
    void validStream() {
        const auto bytes = ps::header() + ps::packet({}, 1700000000, 123456, std::string(60000, 'a')) +
                           ps::packet({}, 1700000001, 654321, std::string(2000, 'b'), 9000);
        streamCase(bytes, 2);
    }
    void segmentedStream() { streamCase(ps::header() + ps::packet({}, 42, 123456, "hello"), 1, {}, 1); }
    void invalidStreams() {
        auto bytes = ps::header(); bytes[0] = 'X';
        streamCase(bytes, 0, "pcap stream");
        streamCase(ps::header().substr(0, 11), 0, "header");
        streamCase(ps::header() + ps::packet({}, 1, 2, "good") + ps::packet({}, 3, 4, "truncated").substr(0, 19), 1, "record");
    }
    void idleStop(bool connected) {
        LiveCapture live;
        auto pipe = makePipe(); const auto path = pipe->path();
        require(live.startFromWorkerPipe(std::move(pipe)), live.lastError());
        HANDLE writer = INVALID_HANDLE_VALUE;
        if (connected) {
            writer = connect(path);
            require(writeBytes(writer, ps::header()), "header write failed");
            require(waitUntil([&] { return live.streaming(); }), "header not received");
        }
        const auto start = std::chrono::steady_clock::now();
        live.stop();
        if (writer != INVALID_HANDLE_VALUE) CloseHandle(writer);
        require(std::chrono::steady_clock::now() - start < 1s, "stop blocked");
        require(!live.running() && live.workerFifoPath().empty(), "stop did not clean up");
    }
    void timeout() {
        LiveCapture live; WorkerStreamOptions options; options.connectTimeoutMs = 80;
        require(live.startFromWorkerPipe(makePipe(), options), live.lastError());
        require(waitUntil([&] { return !live.running(); }), "connect timeout did not finish");
        live.stop(); require(live.lastError().find("Timed out") != std::string::npos, live.lastError());
    }
    void producerFailed() {
        LiveCapture live; WorkerProcess worker;
        worker.start({"not-started"}, [](const auto &) { SpawnResult r; r.error = "Authorization cancelled by the user"; return r; });
        WorkerStreamOptions options;
        options.producerGone = [&] { return worker.exited(); };
        options.finalize = [&](const std::string &) { return describeWorkerFailure(ElevationMethod::RunAs, worker.status(), worker.stderrText()); };
        const auto start = std::chrono::steady_clock::now();
        require(live.startFromWorkerPipe(makePipe(), options), live.lastError());
        require(waitUntil([&] { return !live.running(); }), "failed producer waited for the 5 minute timeout");
        live.stop(); require(std::chrono::steady_clock::now() - start < 1s, "failed producer was not noticed promptly");
        require(live.lastError().find("Authorization cancelled") != std::string::npos, live.lastError());
    }
    void preconnected() {
        auto pipe = makePipe(); HANDLE writer = connect(pipe->path());
        std::atomic<bool> stop{false}; std::string error;
        void *reader = pipe->waitForConnection(1000, stop, error);
        CloseHandle(writer); require(reader != INVALID_HANDLE_VALUE, error);
    }
    void restart() {
        LiveCapture live;
        for (int i = 0; i < 8; ++i) {
            auto pipe = makePipe(); const auto path = pipe->path();
            require(live.startFromWorkerPipe(std::move(pipe)), live.lastError());
            HANDLE writer = connect(path);
            const auto bytes = ps::header() + ps::packet({}, 42, static_cast<uint32_t>(i), "session");
            require(writeBytes(writer, bytes), "write failed"); FlushFileBuffers(writer); CloseHandle(writer);
            require(waitUntil([&] { return !live.running(); }), "restart EOF did not finish");
            live.stop(); require(live.packetCount() == 1, "sessions mixed");
            require(readFile(live.tempPath()) == bytes, "restart file mismatch");
        }
    }
    struct Source : worker::PacketSource {
        int index = 0;
        const std::string body = std::string(100, 'x');
        Status next(worker::SourcePacket &out) override {
            if (index++) return Status::End;
            out = {1700000000, 123456, reinterpret_cast<const unsigned char *>(body.data()), 100, 200};
            return Status::Packet;
        }
    };
    void actualWorkerStream() {
        LiveCapture live; auto pipe = makePipe(); const auto path = pipe->path();
        require(live.startFromWorkerPipe(std::move(pipe)), live.lastError());
        HANDLE writer = connect(path); Source source; std::string error;
        const auto end = worker::streamCapturePipe(writer, source, 1, 64, nullptr, error); CloseHandle(writer);
        require(end == worker::StreamEnd::SourceEnded, error);
        require(waitUntil([&] { return !live.running(); }), "worker stream did not end"); live.stop();
        std::vector<CapturedPacket> packets; live.takePackets(packets);
        require(packets.size() == 1 && packets[0].capturedLength == 64 && packets[0].originalLength == 200, "snaplen/original length mismatch");
        require(packets[0].tsSeconds == 1700000000 && packets[0].tsMicros == 123456, "timestamp mismatch");
        ps::Options options; options.snaplen = 64;
        require(readFile(live.tempPath()) == ps::header(options) + ps::packet(options, 1700000000, 123456, std::string(64, 'x'), 200), "worker file mismatch");
    }
    void idleWorkerExitsWhenReaderCloses() {
        struct IdleSource : worker::PacketSource {
            std::atomic<bool> forceEnd{false};
            Status next(worker::SourcePacket &) override {
                std::this_thread::sleep_for(10ms);
                return forceEnd ? Status::End : Status::Timeout;
            }
        } source;
        LiveCapture live; auto pipe = makePipe(); const auto path = pipe->path();
        require(live.startFromWorkerPipe(std::move(pipe)), live.lastError());
        HANDLE writer = connect(path);
        std::atomic<bool> ended{false}; worker::StreamEnd end = worker::StreamEnd::SourceError;
        std::jthread producer([&] { std::string error; end = worker::streamCapturePipe(writer, source, 1, 64, nullptr, error); ended = true; CloseHandle(writer); });
        const bool headerSeen = waitUntil([&] { return live.streaming(); });
        live.stop();
        const bool exited = waitUntil([&] { return ended.load(); }, 1000);
        source.forceEnd = true; producer.join();
        require(headerSeen, "idle worker header missing");
        require(exited && end == worker::StreamEnd::ReaderGone, "idle worker did not notice the GUI closed its pipe");
    }
    void childWithUnicodePath() {
        const auto dir = core::pathFromUtf8(core::privateTempDir()) / core::pathFromUtf8("Test User İ");
        std::filesystem::create_directory(dir);
        const auto exe = dir / "capture smoke.exe";
        std::filesystem::copy_file(core::pathFromUtf8(currentExecutablePath()), exe, std::filesystem::copy_options::overwrite_existing);
        const auto utf8 = exe.u8string(); const std::string path(utf8.begin(), utf8.end());
        WorkerProcess child;
        child.start({path, "--echo", "space and \"quote\"", "trailing\\", ""});
        require(child.waitExit(3000), "child did not exit");
        require(!child.status().spawnFailed && child.status().code == 0, child.stderrText());
        require(child.stderrText() == "[space and \"quote\"][trailing\\][]", "argument quoting mismatch: " + child.stderrText());
    }
}
int main(int argc, char **argv) {
    if (argc > 1 && std::string(argv[1]) == "--echo") { for (int i = 2; i < argc; ++i) std::cerr << '[' << argv[i] << ']'; return 0; }
    int failures = 0;
    auto run = [&](const char *name, auto test) {
        try { test(); std::cout << "PASS " << name << std::endl; }
        catch (const std::exception &e) { ++failures; std::cerr << "FAIL " << name << ": " << e.what() << std::endl; }
    };
    run("valid stream and exact saved pcap", validStream);
    run("one byte segments", segmentedStream);
    run("malformed and truncated streams retain prior packets", invalidStreams);
    run("stop while connecting", [] { idleStop(false); });
    run("stop connected idle reader", [] { idleStop(true); });
    run("connection timeout", timeout);
    run("failed authorization producer exits promptly", producerFailed);
    run("client connected before server wait", preconnected);
    run("restart isolates sessions", restart);
    run("real worker stream writer snaplen and timestamps", actualWorkerStream);
    run("idle worker exits when GUI closes its pipe", idleWorkerExitsWhenReaderCloses);
    run("child executable Unicode path and quoted arguments", childWithUnicodePath);
    std::cout << "Native IPC scenarios: 12, failed: " << failures << std::endl;
    return failures ? 1 : 0;
}
