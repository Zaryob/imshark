#include "temp_file.h"

#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <mutex>
#include <random>
#include <system_error>

#include <core.h>

#ifdef _WIN32
#  define WIN32_LEAN_AND_MEAN
#  define NOMINMAX
#  include <windows.h>
#else
#  include <cerrno>
#  include <cstdlib>
#  include <cstring>
#  include <fcntl.h>
#  include <unistd.h>
#endif

namespace core {
    namespace {
        std::string randomHex() {
            static std::mutex m;
            static std::random_device rd;   // OS entropy (getrandom / rand_s)
            uint64_t v;
            {
                std::lock_guard<std::mutex> lock(m);
                v = (static_cast<uint64_t>(rd()) << 32) ^ rd();
            }
            char buf[17];
            std::snprintf(buf, sizeof buf, "%016llx", static_cast<unsigned long long>(v));
            return buf;
        }

        struct PrivateDir {
            std::string path;
            std::string error;

            PrivateDir() {
                std::error_code ec;
                const auto base = std::filesystem::temp_directory_path(ec);
                if (ec) { error = "No temporary directory available: " + ec.message(); return; }
#ifdef _WIN32
                // %TEMP% is per-user already; the random name keeps it unpredictable. Default (inherited, user-only) ACLs.
                for (int i = 0; i < 100; ++i) {
                    const auto dir = base / ("imshark_" + randomHex());
                    if (CreateDirectoryW(dir.c_str(), nullptr)) {
                        const auto u8 = dir.u8string();
                        path.assign(u8.begin(), u8.end());
                        return;
                    }
                    if (GetLastError() != ERROR_ALREADY_EXISTS) break;
                }
                error = "Cannot create a private temporary directory";
#else
                std::string tmpl = (base / "imshark_XXXXXX").string();
                if (mkdtemp(tmpl.data()) == nullptr) {
                    error = std::string("Cannot create a private temporary directory: ") + std::strerror(errno);
                    return;
                }
                path = tmpl;   // mkdtemp creates it with mode 0700
#endif
            }

            ~PrivateDir() {
                if (path.empty()) return;
                std::error_code ec;
                std::filesystem::remove_all(pathFromUtf8(path), ec);   // best effort
            }
        };

        PrivateDir &privateDir() {
            static PrivateDir dir;
            return dir;
        }
    } // namespace

    const std::string &privateTempDir() { return privateDir().path; }

    std::string createTempFile(const std::string &suffix, std::string *error) {
        auto &dir = privateDir();
        if (dir.path.empty()) {
            if (error) *error = dir.error;
            return {};
        }
        // a suffix must not be able to leave the directory
        if (suffix.find_first_of("/\\") != std::string::npos) {
            if (error) *error = "Invalid temporary file suffix";
            return {};
        }
        for (int attempt = 0; attempt < 100; ++attempt) {
            const auto path = pathFromUtf8(dir.path) / pathFromUtf8("imshark_" + randomHex() + suffix);
            const auto u8 = path.u8string();
            const std::string utf8(u8.begin(), u8.end());
#ifdef _WIN32
            HANDLE h = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
            if (h != INVALID_HANDLE_VALUE) { CloseHandle(h); return utf8; }
            const DWORD err = GetLastError();
            if (err != ERROR_FILE_EXISTS && err != ERROR_ALREADY_EXISTS) {
                if (error) *error = "Cannot create the temporary file " + utf8;
                return {};
            }
#else
            const int fd = ::open(path.c_str(), O_CREAT | O_EXCL | O_WRONLY | O_NOFOLLOW | O_CLOEXEC, 0600);
            if (fd >= 0) { ::close(fd); return utf8; }
            if (errno != EEXIST) {
                if (error) *error = "Cannot create the temporary file " + utf8 + ": " + std::strerror(errno);
                return {};
            }
#endif
        }
        if (error) *error = "Cannot find a unique temporary file name";
        return {};
    }
} // namespace core
