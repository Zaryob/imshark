#pragma once

// Starting the capture worker (capture_worker.h) with administrator rights. Nothing here ever builds a shell command
// line: the worker command is a vector of arguments, started with posix_spawn, and the only place a shell is involved
// (macOS `do shell script`) quotes every element itself with AppleScript's `quoted form of`.
//
//   Linux:   /usr/bin/pkexec <absolute path of this executable> --capture-worker --interface ... (pkexec execs directly)
//   macOS:   /usr/bin/osascript -e <fixed script> ... -- <exe> --capture-worker ...  (see osascriptScript())
//   Windows: ShellExecuteEx with "runas" verb to request UAC elevation, using a Named Pipe for IPC
//   other:   no elevation (ElevationMethod::None)
//
// The pieces are separate so the tests can exercise them without ever asking for an authorization: the argv builders are
// pure functions, PrivateFifo and spawnProcess work as the current user, and WorkerProcess takes a spawner hook.

#include <atomic>
#include <condition_variable>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "capture_worker.h"

namespace capture {
    enum class ElevationMethod { None, Pkexec, Osascript, RunAs };

    /// What this platform offers: pkexec on Linux, osascript on macOS, RunAs (UAC) on Windows, nothing elsewhere.
    ElevationMethod platformElevationMethod();

    inline const char *const kPkexecPath = "/usr/bin/pkexec";
    inline const char *const kOsascriptPath = "/usr/bin/osascript";

    /// The fixed AppleScript, one `-e` argument per element. It contains no user supplied value: the executable and every
    /// worker argument arrive in `argv` and are quoted by `quoted form of`.
    const std::vector<std::string> &osascriptScript();

    /// {kPkexecPath, exe, workerArgs...}
    std::vector<std::string> buildPkexecArgv(const std::string &exe, const std::vector<std::string> &workerArgs);
    /// {kOsascriptPath, "-e", line, "-e", line, ..., "--", exe, workerArgs...}
    std::vector<std::string> buildOsascriptArgv(const std::string &exe, const std::vector<std::string> &workerArgs);
    /// The argv for `method` (empty for None): workerArgs is worker::workerCommandLine(...).
    std::vector<std::string> buildElevationArgv(ElevationMethod method, const std::string &exe, const std::vector<std::string> &workerArgs);

    /// Absolute path of the running executable (/proc/self/exe on Linux, _NSGetExecutablePath on macOS,
    /// GetModuleFileNameW on Windows); empty if unknown.
    std::string currentExecutablePath();

    // ---- private FIFO (POSIX) / Named Pipe (Windows) ----------------------------------------------------------------
#ifdef _WIN32
    /// A Windows Named Pipe for the capture worker IPC. The pipe name is a random UUID under \\.\pipe\imshark-capture-.
    /// The server (GUI) creates the pipe and gives the name to the worker, which connects as a client.
    /// The pipe has a DACL that permits only the current user's SID and SYSTEM.
    class PrivateNamedPipe {
    public:
        PrivateNamedPipe() = default;
        ~PrivateNamedPipe() { remove(); }
        PrivateNamedPipe(const PrivateNamedPipe &) = delete;
        PrivateNamedPipe &operator=(const PrivateNamedPipe &) = delete;

        /// Creates the named pipe server. Returns false on failure.
        bool create(std::string &error);
        void remove();
        std::string path() const;              // the pipe name (\\.\pipe\imshark-capture-...)

        /// Waits for the worker to connect (blocking, with timeout). Returns the connected pipe handle or
        /// INVALID_HANDLE_VALUE. `stopFlag` is checked periodically.
        void *waitForConnection(int timeoutMs, const std::atomic<bool> &stopFlag, std::string &error);

    private:
        mutable std::mutex mutex_;
        std::string name_;
        void *pipe_ = reinterpret_cast<void *>(static_cast<intptr_t>(-1));   // INVALID_HANDLE_VALUE
    };
#endif

    /// A directory made by mkdtemp (mode 0700, owned by the user) holding a FIFO `capture.fifo` (mode 0600). remove() (also
    /// the destructor) deletes both. POSIX only; create() fails with a message on Windows.
    class PrivateFifo {
    public:
        PrivateFifo() = default;
        ~PrivateFifo() { remove(); }
        PrivateFifo(const PrivateFifo &) = delete;
        PrivateFifo &operator=(const PrivateFifo &) = delete;

        bool create(std::string &error);
        void remove();                         // idempotent
        std::string path() const;              // the FIFO ("" before create / after remove)
        std::string directory() const;

    private:
        mutable std::mutex mutex_;
        std::string dir_, path_;
    };

    // ---- processes -----------------------------------------------------------------------------------------------
    struct SpawnResult {
        bool ok = false;
        long pid = -1;                 // the child (POSIX pid or Windows process id)
        int stderrFd = -1;             // read end of the pipe connected to the child's stderr (the caller owns it)
#ifdef _WIN32
        void *processHandle = nullptr; // HANDLE to the child process (Windows)
        void *stderrHandle = nullptr;  // HANDLE to the stderr read pipe (Windows)
#endif
        std::string error;             // when !ok
    };

    /// Starts a child process with stdin/stdout on /dev/null (NUL on Windows) and stderr on a pipe.
    /// POSIX: posix_spawn(argv[0], argv), argv[0] must be an absolute path.
    /// Windows: CreateProcessW, argv[0] must be an absolute path.
    SpawnResult spawnProcess(const std::vector<std::string> &argv);

    /// Windows only: starts `exe` elevated through UAC (ShellExecuteEx with "runas"), passing `args` as a single
    /// quoted command line. Returns ok=true if the process started. stderr is not captured (UAC child inherits nothing).
    SpawnResult spawnElevated(const std::string &exe, const std::vector<std::string> &args);

    struct ProcessExit {
        bool exited = false;           // reaped
        bool spawnFailed = false;
        int code = -1;                 // exit status (valid if !signaled)
        int signal = 0;                // terminating signal, 0 if none
    };

    /// One-line, user readable explanation of why the elevated worker did not deliver packets: pkexec 126/127, osascript
    /// -128 (cancelled), the worker's own stderr line, ... `stderrText` is what the child printed.
    std::string describeWorkerFailure(ElevationMethod method, const ProcessExit &exit, const std::string &stderrText);

    /// The worker process started on a background thread (spawn + waitpid + stderr collection), so the GUI never blocks on
    /// an authorization dialog. The thread owns shared state, so abandon() never has to wait for it.
    class WorkerProcess {
    public:
        using Spawner = std::function<SpawnResult(const std::vector<std::string> &)>;

        WorkerProcess() = default;
        ~WorkerProcess() { abandon(); }
        WorkerProcess(const WorkerProcess &) = delete;
        WorkerProcess &operator=(const WorkerProcess &) = delete;

        /// Returns immediately; the thread spawns `argv` with `spawner` (default: spawnProcess).
        void start(std::vector<std::string> argv, Spawner spawner = {});
        bool exited() const;
        ProcessExit status() const;
        std::string stderrText() const;
        /// true if the child ended or `ms` passed.
        bool waitExit(int ms) const;
        /// Cancels: SIGTERM now if the child still runs (TerminateProcess on Windows); returns at once.
        void abandon();

    private:
        struct State;
        std::shared_ptr<State> state_;
    };
} // namespace capture
