#include "worker_launch.h"

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <cstring>
#include <filesystem>

#ifndef _WIN32
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
    } // namespace

    ElevationMethod platformElevationMethod() {
#if defined(__APPLE__)
        return ElevationMethod::Osascript;
#elif defined(__linux__)
        return ElevationMethod::Pkexec;
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
    SpawnResult spawnProcess(const std::vector<std::string> &) {
        SpawnResult r;
        r.error = "Starting the capture worker is not supported on this platform";
        return r;
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
#endif

    // ---- failure text -------------------------------------------------------------------------------------------------
    std::string describeWorkerFailure(ElevationMethod method, const ProcessExit &exit, const std::string &stderrText) {
        const std::string text = oneLine(stderrText);
        if (exit.spawnFailed) {
            if (method == ElevationMethod::Pkexec) return "pkexec could not be started (is polkit installed?): " + text;
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
    };

    namespace {
#ifndef _WIN32
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
            std::lock_guard<std::mutex> lock(s->mutex);
            s->exit.exited = true;
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
#ifndef _WIN32
        if (s->pid > 0 && !s->exit.exited) ::kill(static_cast<pid_t>(s->pid), SIGTERM);
#endif
        if (s->thread.joinable()) s->thread.detach();
    }
} // namespace capture
