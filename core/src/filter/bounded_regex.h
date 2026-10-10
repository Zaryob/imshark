#pragma once

// Regular expressions with a hard work bound, for patterns typed by the user or read from the settings file that are
// run against values taken from untrusted captures. Backed by PCRE2 (Perl-compatible syntax, like Wireshark) in
// interpreter mode with a match, depth and heap limit, so a catastrophic pattern ends in a counted "no match" instead
// of a stall. Matching is byte oriented (no UTF mode): a value that is not valid UTF-8 is searched like any other.

#include <cstddef>
#include <memory>
#include <string>
#include <string_view>

namespace filter {
    class BoundedRegex {
    public:
        enum class Outcome {
            NoMatch,
            Match,
            LimitExceeded // the work bound was hit; the value counts as "no match" but is reported
        };

        struct Compiled;

        /// Compiles `pattern`. On failure `ok` is false, `message` holds the PCRE2 text and `offset` the byte position
        /// in the pattern where it gave up.
        struct Result;
        static Result compile(std::string_view pattern);

        /// Unanchored search of `text`. Thread safe: the compiled pattern is immutable and shared, match state is
        /// per thread.
        Outcome search(std::string_view text) const;

    private:
        std::shared_ptr<const Compiled> compiled_;
    };

    struct BoundedRegex::Result {
        bool ok = false;
        BoundedRegex regex;
        std::string message;
        size_t offset = 0;
    };
} // namespace filter
