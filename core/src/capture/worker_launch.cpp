#include "worker_launch.h"

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <cstring>
#include <filesystem>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <shellapi.h>
#include <sddl.h>
#include <objbase.h>    // CoCreateGuid
#else
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <spawn.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#ifdef __APPLE__
#include <mach-o/dyld.h>
#endif
extern char **environ;
#endif

namespace capture {
    namespace {
        constexpr size_t kMaxStderrBytes = 16 * 1024;

        std::string oneLine(std::string text, size_t limit = 400) {
            for (char &c: text) {
                if (c == '\n' || c == '\r' || c == '\t') c = ' ';
            }
            const size_t first = text.find_first_not_of(' ');
            if (first == std::string::npos) return {};
            text = text.substr(first, text.find_last_not_of(' ') - first + 1);
            if (text.size() > limit) text = text.substr(0, limit) + "...";
            return text;
        }

#ifdef _WIN32
        std::string wideToUtf8(const std::wstring &wide) {
            if (wide.empty()) return {};
            const int n = WideCharToMultiByte(CP_UTF8, 0, wide.data(), static_cast<int>(wide.size()), nullptr, 0, nullptr, nullptr);
            if (n <= 0) return {};
            std::string out(static_cast<size_t>(n), '\0');
            WideCharToMultiByte(CP_UTF8, 0, wide.data(), static_cast<int>(wide.size()), out.data(), n, nullptr, nullptr);
            return out;
        }

        std::wstring utf8ToWide(const std::string &utf8) {
            if (utf8.empty()) return {};
            const int n = MultiByteToWideChar(CP_UTF8, 0, utf8.data(), static_cast<int>(utf8.size()), nullptr, 0);
            if (n <= 0) return {};
            std::wstring out(static_cast<size_t>(n), L'\0');
            MultiByteToWideChar(CP_UTF8, 0, utf8.data(), static_cast<int>(utf8.size()), out.data(), n);
            return out;
        }

        // Generate a unique pipe name using CoCreateGuid.
        std::string generatePipeName() {
            GUID guid{};
            if (CoCreateGuid(&guid) != S_OK) {
                // Fallback: use tick count and process id.
                return "\\\\.\\pipe\\imshark-capture-" + std::to_string(GetCurrentProcessId()) + "-" + std::to_string(GetTickCount64());
            }
            wchar_t buf[64];
            StringFromGUID2(guid, buf, 64);
            return "\\\\.\\pipe\\imshark-capture-" + wideToUtf8(buf);
        }

        // Quote a single argument for the Windows command line (CreateProcess rules).
        std::wstring quoteArgW(const std::string &arg) {
            const std::wstring wide = utf8ToWide(arg);
            // If it contains no special characters, return as-is.
            if (wide.find_first_of(L" \t\"") == std::wstring::npos) return wide;
            std::wstring out = L"\"";
            for (size_t i = 0; i < wide.size(); ++i) {
                size_t backslashes = 0;
                while (i < wide.size() && wide[i] == L'\\') { ++backslashes; ++i; }
                if (i == wide.size()) {
                    out.append(backslashes * 2, L'\\');
                    break;
                } else if (wide[i] == L'"') {
                    out.append(backslashes * 2 + 1, L'\\');
                    out += L'"';
                } else {
                    out.append(backslashes, L'\\');
                    out += wide[i];
                }
            }
            return out + L'"';
        }

        std::wstring buildCommandLine(const std::vector<std::string> &argv) {
            std::wstring cmd;
            for (size_t i = 0; i < argv.size(); ++i) {
                if (i > 0) cmd += L' ';
                cmd += quoteArgW(argv[i]);
            }
            return cmd;
        }
#endif
    } // namespace

    ElevationMethod platformElevationMethod() {
#if defined(__APPLE__)
        return ElevationMethod::Osascript;
#elif defined(__linux__)
        return ElevationMethod::Pkexec;
#elif defined(_WIN32)
        return ElevationMethod::RunAs;
#else
        return ElevationMethod::None;
#endif
    }

    const std::vector<std::string> &osascriptScript() {
        // Fixed text. `argv` holds the executable and the worker arguments; `quoted form of` makes each one a single,
        // safely quoted shell word, so the string handed to `do shell script` is never parsed from anything we built.
        static const std::vector<std::string> script = {
            "on run argv",
            "set cmd to quoted form of (item 1 of argv)",
            "repeat with i from 2 to (count of argv)",
            "set cmd to cmd & \" \" & (quoted form of (item i of argv))",
            "end repeat",
            "do shell script cmd with administrator privileges",
            "end run",
        };
        return script;
    }

    std::vector<std::string> buildPkexecArgv(const std::string &exe, const std::vector<std::string> &workerArgs) {
        std::vector<std::string> argv = {kPkexecPath, exe};
        argv.insert(argv.end(), workerArgs.begin(), workerArgs.end());
        return argv;
    }

    std::vector<std::string> buildOsascriptArgv(const std::string &exe, const std::vector<std::string> &workerArgs) {
        std::vector<std::string> argv = {kOsascriptPath};
        for (const std::string &line: osascriptScript()) {
            argv.push_back("-e");
            argv.push_back(line);
        }
        argv.push_back("--");
        argv.push_back(exe);
        argv.insert(argv.end(), workerArgs.begin(), workerArgs.end());
        return argv;
    }

    std::vector<std::string> buildElevationArgv(ElevationMethod method, const std::string &exe, const std::vector<std::string> &workerArgs) {
        switch (method) {
            case ElevationMethod::Pkexec: return buildPkexecArgv(exe, workerArgs);
            case ElevationMethod::Osascript: return buildOsascriptArgv(exe, workerArgs);
            case ElevationMethod::RunAs: {
                // On Windows the RunAs elevation argv is just {exe, workerArgs...}; spawnElevated handles the UAC verb.
                std::vector<std::string> argv = {exe};
                argv.insert(argv.end(), workerArgs.begin(), workerArgs.end());
                return argv;
            }
            case ElevationMethod::None: break;
        }
        return {};
    }

    std::string currentExecutablePath() {
#if defined(__linux__)
        char buf[4096];
        const ssize_t n = ::readlink("/proc/self/exe", buf, sizeof buf - 1);
        if (n <= 0) return {};
        return std::string(buf, static_cast<size_t>(n));
#elif defined(__APPLE__)
        char buf[4096];
        uint32_t size = sizeof buf;
        if (_NSGetExecutablePath(buf, &size) != 0) return {};
        char real[4096];
        if (!::realpath(buf, real)) return std::string(buf);
        return real;
#elif defined(_WIN32)
        wchar_t buf[4096];
        const DWORD n = GetModuleFileNameW(nullptr, buf, 4096);
        if (n == 0 || n >= 4096) return {};
        return wideToUtf8(std::wstring(buf, n));
#else
        return {};
#endif
    }

    // ---- PrivateFifo --------------------------------------------------------------------------------------------------
#ifdef _WIN32
    bool PrivateFifo::create(std::string &error) {
        error = "Named pipes for the capture worker are not supported on this platform";
        return false;
    }
    void PrivateFifo::remove() {}

    // ---- PrivateNamedPipe ---------------------------------------------------------------------------------------------
    bool PrivateNamedPipe::create(std::string &error) {
        remove();
        const std::string name = generatePipeName();

        // Create a Named Pipe with a restrictive DACL: allow only the current user (OWNER) and SYSTEM full control.
        // "D:(A;;GA;;;SY)(A;;GA;;;OW)" = DACL: Allow Generic All to SYSTEM and Owner.
        SECURITY_ATTRIBUTES sa{};
        sa.nLength = sizeof(sa);
        sa.bInheritHandle = FALSE;
        PSECURITY_DESCRIPTOR sd = nullptr;
        if (!ConvertStringSecurityDescriptorToSecurityDescriptorA(
                "D:(A;;GA;;;SY)(A;;GA;;;OW)", SDDL_REVISION_1, &sd, nullptr)) {
            error = "Cannot create security descriptor for the capture pipe";
            return false;
        }
        sa.lpSecurityDescriptor = sd;

        HANDLE h = CreateNamedPipeA(
            name.c_str(),
            PIPE_ACCESS_INBOUND | FILE_FLAG_OVERLAPPED,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
            1,         // max instances
            0,         // output buffer
            256 * 1024, // input buffer
            0,         // default timeout
            &sa);
        LocalFree(sd);

        if (h == INVALID_HANDLE_VALUE) {
            error = "Cannot create the capture pipe: error " + std::to_string(GetLastError());
            return false;
        }
        std::lock_guard<std::mutex> lock(mutex_);
        name_ = name;
        pipe_ = h;
        return true;
    }

    void PrivateNamedPipe::remove() {
        HANDLE h;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            h = pipe_;
            pipe_ = INVALID_HANDLE_VALUE;
            name_.clear();
        }
        if (h != INVALID_HANDLE_VALUE) {
            DisconnectNamedPipe(h);
            CloseHandle(h);
        }
    }

    std::string PrivateNamedPipe::path() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return name_;
    }

    void *PrivateNamedPipe::waitForConnection(int timeoutMs, const std::atomic<bool> &stopFlag, std::string &error,
                                              const std::function<bool()> &producerGone) {
        HANDLE h;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            h = pipe_;
        }
        if (h == INVALID_HANDLE_VALUE) {
            error = "The capture pipe was not created";
            return INVALID_HANDLE_VALUE;
        }

        OVERLAPPED ov{};
        ov.hEvent = CreateEventA(nullptr, TRUE, FALSE, nullptr);
        if (!ov.hEvent) {
            error = "Cannot create event for pipe connection";
            return INVALID_HANDLE_VALUE;
        }

        BOOL connected = ConnectNamedPipe(h, &ov);
        DWORD lastErr = connected ? ERROR_SUCCESS : GetLastError();
        if (connected || lastErr == ERROR_PIPE_CONNECTED) {
            // Already connected.
            CloseHandle(ov.hEvent);
            return h;
        }
        if (!connected && lastErr != ERROR_IO_PENDING) {
            error = "ConnectNamedPipe failed: error " + std::to_string(lastErr);
            CloseHandle(ov.hEvent);
            return INVALID_HANDLE_VALUE;
        }

        // Wait with periodic checks for stopFlag.
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeoutMs);
        while (!stopFlag && !(producerGone && producerGone()) && std::chrono::steady_clock::now() < deadline) {
            DWORD wait = WaitForSingleObject(ov.hEvent, 20);
            if (wait == WAIT_OBJECT_0) {
                DWORD bytes = 0;
                if (GetOverlappedResult(h, &ov, &bytes, FALSE)) {
                    CloseHandle(ov.hEvent);
                    return h;
                }
                error = "Pipe connection failed: error " + std::to_string(GetLastError());
                CloseHandle(ov.hEvent);
                return INVALID_HANDLE_VALUE;
            }
        }
        CancelIoEx(h, &ov);
        DWORD ignored = 0;
        GetOverlappedResult(h, &ov, &ignored, TRUE); // cancellation must finish before ov/event go out of scope
        CloseHandle(ov.hEvent);
        if (stopFlag) {
            error = "Pipe connection cancelled";
        } else if (producerGone && producerGone()) {
            error = "The capture helper ended before connecting";
        } else {
            error = "Timed out waiting for the capture helper to connect";
        }
        return INVALID_HANDLE_VALUE;
    }
#else
    bool PrivateFifo::create(std::string &error) {
        remove();
        std::error_code ec;
        std::string templ = (std::filesystem::temp_directory_path(ec) / "imshark-capture-XXXXXX").string();
        if (ec) {
            error = "Cannot find the temporary directory: " + ec.message();
            return false;
        }
        std::vector<char> buf(templ.begin(), templ.end());
        buf.push_back('\0');
        if (!::mkdtemp(buf.data())) {
            error = std::string("Cannot create a private directory for the capture pipe: ") + std::strerror(errno);
            return false;
        }
        const std::string dir = buf.data();
        struct stat st {};
        if (::lstat(dir.c_str(), &st) != 0 || !S_ISDIR(st.st_mode) || st.st_uid != ::geteuid() || (st.st_mode & 0777) != 0700) {
            error = "The private directory for the capture pipe has unexpected permissions";
            ::rmdir(dir.c_str());
            return false;
        }
        const std::string fifo = dir + "/capture.fifo";
        if (::mkfifo(fifo.c_str(), 0600) != 0) {
            error = std::string("Cannot create the capture pipe: ") + std::strerror(errno);
            ::rmdir(dir.c_str());
            return false;
        }
        ::chmod(fifo.c_str(), 0600);     // the umask can only have removed bits; make the mode exact
        if (::lstat(fifo.c_str(), &st) != 0 || !S_ISFIFO(st.st_mode) || st.st_uid != ::geteuid()) {
            error = "The capture pipe has unexpected properties";
            ::unlink(fifo.c_str());
            ::rmdir(dir.c_str());
            return false;
        }
        std::lock_guard<std::mutex> lock(mutex_);
        dir_ = dir;
        path_ = fifo;
        return true;
    }

    void PrivateFifo::remove() {
        std::string dir, path;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            dir.swap(dir_);
            path.swap(path_);
        }
        if (!path.empty()) ::unlink(path.c_str());
        if (!dir.empty()) ::rmdir(dir.c_str());
    }
#endif

    std::string PrivateFifo::path() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return path_;
    }

    std::string PrivateFifo::directory() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return dir_;
    }

    // ---- spawn --------------------------------------------------------------------------------------------------------
#ifdef _WIN32
    SpawnResult spawnProcess(const std::vector<std::string> &argv) {
        SpawnResult result;
        if (argv.empty() || argv[0].empty()) {
            result.error = "The program to start must be specified";
            return result;
        }

        // Create a pipe for stderr.
        SECURITY_ATTRIBUTES psa{};
        psa.nLength = sizeof(psa);
        psa.bInheritHandle = TRUE;
        HANDLE stderrRead = nullptr, stderrWrite = nullptr;
        if (!CreatePipe(&stderrRead, &stderrWrite, &psa, 0)) {
            result.error = "Cannot create stderr pipe: error " + std::to_string(GetLastError());
            return result;
        }
        SetHandleInformation(stderrRead, HANDLE_FLAG_INHERIT, 0);  // read end is not inherited

        // NUL device for stdin/stdout.
        HANDLE hNul = CreateFileA("NUL", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
                                  &psa, OPEN_EXISTING, 0, nullptr);

        STARTUPINFOW si{};
        si.cb = sizeof(si);
        si.dwFlags = STARTF_USESTDHANDLES;
        si.hStdInput = hNul;
        si.hStdOutput = hNul;
        si.hStdError = stderrWrite;

        PROCESS_INFORMATION pi{};
        std::wstring cmdLine = buildCommandLine(argv);
        BOOL ok = CreateProcessW(
            utf8ToWide(argv[0]).c_str(),
            cmdLine.data(),
            nullptr, nullptr,
            TRUE,   // inherit handles
            CREATE_NO_WINDOW,
            nullptr, nullptr,
            &si, &pi);

        CloseHandle(hNul);
        CloseHandle(stderrWrite);

        if (!ok) {
            CloseHandle(stderrRead);
            result.error = "Cannot start " + argv[0] + ": error " + std::to_string(GetLastError());
            return result;
        }
        CloseHandle(pi.hThread);

        result.ok = true;
        result.pid = static_cast<long>(pi.dwProcessId);
        result.processHandle = pi.hProcess;
        result.stderrHandle = stderrRead;
        return result;
    }

    SpawnResult spawnElevated(const std::string &exe, const std::vector<std::string> &args) {
        SpawnResult result;
        // Build the parameter string (everything after the exe).
        std::wstring params;
        for (size_t i = 1; i < args.size(); ++i) {
            if (i > 1) params += L' ';
            params += quoteArgW(args[i]);
        }

        SHELLEXECUTEINFOW sei{};
        sei.cbSize = sizeof(sei);
        sei.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC;
        sei.lpVerb = L"runas";
        const std::wstring executable = utf8ToWide(exe);
        sei.lpFile = executable.c_str();
        sei.lpParameters = params.c_str();
        sei.nShow = SW_HIDE;

        if (!ShellExecuteExW(&sei)) {
            DWORD err = GetLastError();
            if (err == ERROR_CANCELLED) {
                result.error = "Authorization cancelled by the user";
            } else {
                result.error = "Cannot start elevated process: error " + std::to_string(err);
            }
            return result;
        }
        result.ok = true;
        result.processHandle = sei.hProcess;
        result.pid = static_cast<long>(GetProcessId(sei.hProcess));
        return result;
    }
#else
    SpawnResult spawnProcess(const std::vector<std::string> &argv) {
        SpawnResult result;
        if (argv.empty() || argv[0].empty() || argv[0][0] != '/') {
            result.error = "The program to start must be an absolute path";
            return result;
        }
        int fds[2];
        if (::pipe(fds) != 0) {
            result.error = std::string("pipe failed: ") + std::strerror(errno);
            return result;
        }
        ::fcntl(fds[0], F_SETFD, FD_CLOEXEC);
        ::fcntl(fds[1], F_SETFD, FD_CLOEXEC);
        std::vector<char *> args;
        args.reserve(argv.size() + 1);
        for (const std::string &a: argv) args.push_back(const_cast<char *>(a.c_str()));
        args.push_back(nullptr);

        posix_spawn_file_actions_t actions;
        posix_spawnattr_t attr;
        posix_spawn_file_actions_init(&actions);
        posix_spawnattr_init(&attr);
        posix_spawn_file_actions_addopen(&actions, 0, "/dev/null", O_RDONLY, 0);
        posix_spawn_file_actions_addopen(&actions, 1, "/dev/null", O_WRONLY, 0);
        posix_spawn_file_actions_adddup2(&actions, fds[1], 2);
#ifdef __APPLE__
        posix_spawnattr_setflags(&attr, POSIX_SPAWN_CLOEXEC_DEFAULT);   // nothing but 0, 1, 2 reaches the child
#endif
        pid_t pid = 0;
        const int rc = ::posix_spawn(&pid, argv[0].c_str(), &actions, &attr, args.data(), environ);
        posix_spawn_file_actions_destroy(&actions);
        posix_spawnattr_destroy(&attr);
        ::close(fds[1]);
        if (rc != 0) {
            ::close(fds[0]);
            result.error = "Cannot start " + argv[0] + ": " + std::strerror(rc);
            return result;
        }
        ::fcntl(fds[0], F_SETFL, ::fcntl(fds[0], F_GETFL) | O_NONBLOCK);
        result.ok = true;
        result.pid = static_cast<long>(pid);
        result.stderrFd = fds[0];
        return result;
    }

    SpawnResult spawnElevated(const std::string &, const std::vector<std::string> &) {
        SpawnResult r;
        r.error = "UAC elevation is only available on Windows";
        return r;
    }
#endif

    // ---- failure text -------------------------------------------------------------------------------------------------
    std::string describeWorkerFailure(ElevationMethod method, const ProcessExit &exit, const std::string &stderrText) {
        const std::string text = oneLine(stderrText);
        if (exit.spawnFailed) {
            if (method == ElevationMethod::Pkexec) return "pkexec could not be started (is polkit installed?): " + text;
            if (method == ElevationMethod::RunAs) return "Administrator elevation failed: " + text;
            return "The authorization helper could not be started: " + text;
        }
        if (!exit.exited) return "The capture helper is still running";
        // the worker's own one-line message, also when osascript wrapped it into an AppleScript error
        const std::string marker = "imshark-capture-worker:";
        const size_t at = stderrText.find(marker);
        if (at != std::string::npos) {
            std::string line = stderrText.substr(at + marker.size());
            line = line.substr(0, line.find('\n'));
            const size_t paren = line.rfind(" (");      // osascript appends " (<exit status>)"
            if (paren != std::string::npos && line.find(')', paren) != std::string::npos && paren > 0 && line.back() == ')') line = line.substr(0, paren);
            return "Capture helper: " + oneLine(line);
        }
        if (exit.signal != 0) return "The capture helper was terminated by signal " + std::to_string(exit.signal) + (text.empty() ? "" : ": " + text);
        if (exit.code == 0) return {};
        if (method == ElevationMethod::Osascript) {
            if (stderrText.find("(-128)") != std::string::npos || stderrText.find("User canceled") != std::string::npos) return "Authorization cancelled";
            return "Administrator authorization failed" + (text.empty() ? "" : ": " + text);
        }
        if (method == ElevationMethod::Pkexec) {
            if (exit.code == 126) return "Authorization was dismissed or denied" + (text.empty() ? "" : ": " + text);
            if (exit.code == 127) {
                return "Administrator authorization could not be obtained (no polkit authentication agent is running, or you are not allowed to use pkexec)" +
                       (text.empty() ? "" : ": " + text);
            }
        }
        if (method == ElevationMethod::RunAs) {
            return "The elevated capture helper failed with exit status " + std::to_string(exit.code) + (text.empty() ? "" : ": " + text);
        }
        return "The capture helper failed with exit status " + std::to_string(exit.code) + (text.empty() ? "" : ": " + text);
    }

    // ---- WorkerProcess ------------------------------------------------------------------------------------------------
    struct WorkerProcess::State {
        mutable std::mutex mutex;
        mutable std::condition_variable cv;
        ProcessExit exit;
        std::string stderrText;
        long pid = -1;
        bool finished = false;      // the thread is done: stderrText is complete
        bool abandoned = false;
        bool killSent = false;
        std::chrono::steady_clock::time_point abandonedAt;
        std::thread thread;
#ifdef _WIN32
        HANDLE processHandle = nullptr;
#endif
    };

    namespace {
#ifdef _WIN32
        void readStderrWin(HANDLE h, std::string &into) {
            char buf[1024];
            DWORD avail = 0;
            while (PeekNamedPipe(h, nullptr, 0, nullptr, &avail, nullptr) && avail > 0) {
                DWORD n = 0;
                if (ReadFile(h, buf, sizeof(buf), &n, nullptr) && n > 0) {
                    if (into.size() < kMaxStderrBytes) into.append(buf, std::min<size_t>(n, kMaxStderrBytes - into.size()));
                } else {
                    break;
                }
            }
        }
#else
        void readStderr(int fd, std::string &into) {
            char buf[1024];
            while (true) {
                const ssize_t n = ::read(fd, buf, sizeof buf);
                if (n > 0) {
                    if (into.size() < kMaxStderrBytes) into.append(buf, static_cast<size_t>(std::min<size_t>(static_cast<size_t>(n), kMaxStderrBytes - into.size())));
                    continue;
                }
                if (n < 0 && errno == EINTR) continue;
                return;
            }
        }
#endif
    } // namespace

    void WorkerProcess::start(std::vector<std::string> argv, Spawner spawner) {
        abandon();
        auto s = std::make_shared<State>();
        state_ = s;
        s->thread = std::thread([s, argv = std::move(argv), spawner = std::move(spawner)] {
            const SpawnResult r = spawner ? spawner(argv) : spawnProcess(argv);
            if (!r.ok) {
                std::lock_guard<std::mutex> lock(s->mutex);
                s->exit.exited = true;
                s->exit.spawnFailed = true;
                s->stderrText = r.error;
                s->finished = true;
                s->cv.notify_all();
                return;
            }
#ifdef _WIN32
            {
                std::lock_guard<std::mutex> lock(s->mutex);
                s->pid = r.pid;
                s->processHandle = r.processHandle;
            }
            std::string collected;
            bool done = false;
            while (!done) {
                if (r.stderrHandle) {
                    readStderrWin(r.stderrHandle, collected);
                }
                {
                    std::lock_guard<std::mutex> lock(s->mutex);
                    if (s->abandoned && !s->killSent && s->processHandle &&
                        std::chrono::steady_clock::now() - s->abandonedAt > std::chrono::milliseconds(1500)) {
                        TerminateProcess(static_cast<HANDLE>(s->processHandle), 1);
                        s->killSent = true;
                    }
                }
                DWORD waitResult = WaitForSingleObject(static_cast<HANDLE>(r.processHandle), 50);
                if (waitResult == WAIT_OBJECT_0) {
                    DWORD exitCode = 0;
                    GetExitCodeProcess(static_cast<HANDLE>(r.processHandle), &exitCode);
                    std::lock_guard<std::mutex> lock(s->mutex);
                    s->exit.exited = true;
                    s->exit.code = static_cast<int>(exitCode);
                    done = true;
                } else if (waitResult == WAIT_FAILED) {
                    std::lock_guard<std::mutex> lock(s->mutex);
                    s->exit.exited = true;
                    done = true;
                }
            }
            if (r.stderrHandle) {
                readStderrWin(r.stderrHandle, collected);
                CloseHandle(r.stderrHandle);
            }
            CloseHandle(r.processHandle);
            std::lock_guard<std::mutex> lock(s->mutex);
            s->stderrText = collected;
            s->processHandle = nullptr;
            s->finished = true;
            s->cv.notify_all();
#else
            {
                std::lock_guard<std::mutex> lock(s->mutex);
                s->pid = r.pid;
                if (s->abandoned) ::kill(static_cast<pid_t>(r.pid), SIGTERM);
            }
            std::string collected;
            bool done = false;
            while (!done) {
                if (r.stderrFd >= 0) {
                    pollfd p{r.stderrFd, POLLIN, 0};
                    ::poll(&p, 1, 50);
                    readStderr(r.stderrFd, collected);
                } else {
                    std::this_thread::sleep_for(std::chrono::milliseconds(50));
                }
                std::lock_guard<std::mutex> lock(s->mutex);
                if (s->abandoned && !s->killSent && std::chrono::steady_clock::now() - s->abandonedAt > std::chrono::milliseconds(1500)) {
                    ::kill(static_cast<pid_t>(r.pid), SIGKILL);
                    s->killSent = true;
                }
                int status = 0;
                const pid_t w = ::waitpid(static_cast<pid_t>(r.pid), &status, WNOHANG);
                if (w == static_cast<pid_t>(r.pid)) {
                    s->exit.exited = true;
                    if (WIFEXITED(status)) s->exit.code = WEXITSTATUS(status);
                    if (WIFSIGNALED(status)) s->exit.signal = WTERMSIG(status);
                    done = true;
                } else if (w < 0 && errno != EINTR) {
                    s->exit.exited = true;      // not our child any more (or never): nothing left to wait for
                    done = true;
                }
            }
            if (r.stderrFd >= 0) {
                readStderr(r.stderrFd, collected);
                ::close(r.stderrFd);
            }
            std::lock_guard<std::mutex> lock(s->mutex);
            s->stderrText = collected;
            s->finished = true;
            s->cv.notify_all();
#endif
        });
    }

    bool WorkerProcess::exited() const {
        if (!state_) return false;
        std::lock_guard<std::mutex> lock(state_->mutex);
        return state_->exit.exited;
    }

    ProcessExit WorkerProcess::status() const {
        if (!state_) return {};
        std::lock_guard<std::mutex> lock(state_->mutex);
        return state_->exit;
    }

    std::string WorkerProcess::stderrText() const {
        if (!state_) return {};
        std::lock_guard<std::mutex> lock(state_->mutex);
        return state_->stderrText;
    }

    bool WorkerProcess::waitExit(int ms) const {
        if (!state_) return true;
        std::unique_lock<std::mutex> lock(state_->mutex);
        return state_->cv.wait_for(lock, std::chrono::milliseconds(ms), [&] { return state_->finished; });
    }

    void WorkerProcess::abandon() {
        if (!state_) return;
        std::shared_ptr<State> s = std::move(state_);
        state_.reset();
        std::lock_guard<std::mutex> lock(s->mutex);
        if (s->abandoned) return;
        s->abandoned = true;
        s->abandonedAt = std::chrono::steady_clock::now();
#ifdef _WIN32
        if (s->processHandle && !s->exit.exited) {
            TerminateProcess(static_cast<HANDLE>(s->processHandle), 1);
        }
#else
        if (s->pid > 0 && !s->exit.exited) ::kill(static_cast<pid_t>(s->pid), SIGTERM);
#endif
        if (s->thread.joinable()) s->thread.detach();
    }
} // namespace capture
