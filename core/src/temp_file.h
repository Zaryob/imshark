#pragma once

// Safe temporary files. The predictable names `imshark_<clock>_<n>` that used to be created directly in the shared
// temp directory could be pre-planted as symlinks by another local user (ImShark would then truncate the victim's
// file) and were created with the default umask, so captured traffic was often world-readable.
//
// Design: one private directory per process, created once with mkdtemp (POSIX, mode 0700; on Windows a randomly
// named directory below the per-user %TEMP%). Every temporary file lives inside it and is created exclusively
// (O_CREAT|O_EXCL|O_NOFOLLOW, mode 0600 / CREATE_NEW), so an existing file or symlink is never opened. The creator
// closes the descriptor and returns the path; callers reopen it with std::ofstream (which cannot adopt an fd
// portably). That reopen is safe because nobody but the owner can enter the 0700 directory to swap the file.
// The directory is removed with its contents at normal process exit (best effort).

#include <string>

namespace core {
    /// The per-process private directory, created on first use. Empty if it could not be created.
    const std::string &privateTempDir();

    /// Creates a new, empty, owner-only file with a unique random name ending in `suffix` inside privateTempDir().
    /// Returns its UTF-8 path, or an empty string on failure (`error`, if given, receives the reason).
    std::string createTempFile(const std::string &suffix, std::string *error = nullptr);
} // namespace core
