#include "bounded_regex.h"

#define PCRE2_CODE_UNIT_WIDTH 8
#include <pcre2.h>

namespace filter {
    namespace {
        // Work bounds of one search (one pcre2_match call, however many start positions it tries). Sized so that every
        // sensible pattern over a packet summary finishes far inside them (a `.*` over a 4 KiB value needs a few
        // thousand steps) while a catastrophic one stops after a few milliseconds.
        constexpr uint32_t kMatchLimit = 100000;   // backtracking points
        constexpr uint32_t kDepthLimit = 1000;     // nested backtracking depth
        constexpr uint32_t kHeapLimitKiB = 1024;   // 1 MiB of match heap

        struct ContextDeleter { void operator()(pcre2_match_context *c) const { pcre2_match_context_free(c); } };
        struct DataDeleter { void operator()(pcre2_match_data *d) const { pcre2_match_data_free(d); } };
        struct CodeDeleter { void operator()(pcre2_code *c) const { pcre2_code_free(c); } };

        pcre2_match_data *threadMatchData() {
            // Only "did it match" is needed, so one ovector pair serves every pattern; one block per thread.
            thread_local std::unique_ptr<pcre2_match_data, DataDeleter> data(pcre2_match_data_create(1, nullptr));
            return data.get();
        }
    } // namespace

    struct BoundedRegex::Compiled {
        std::unique_ptr<pcre2_code, CodeDeleter> code;
        std::unique_ptr<pcre2_match_context, ContextDeleter> context; // read-only while matching
    };

    BoundedRegex::Result BoundedRegex::compile(std::string_view pattern) {
        Result result;
        int errorCode = 0;
        PCRE2_SIZE errorOffset = 0;
        // No PCRE2_UTF: values may be arbitrary bytes. Case sensitive unless the pattern says (?i).
        pcre2_code *code = pcre2_compile(reinterpret_cast<PCRE2_SPTR>(pattern.data()), pattern.size(), 0, &errorCode,
                                         &errorOffset, nullptr);
        if (!code) {
            PCRE2_UCHAR buffer[256];
            const int n = pcre2_get_error_message(errorCode, buffer, sizeof buffer);
            result.message = n > 0 ? std::string(reinterpret_cast<char *>(buffer), static_cast<size_t>(n)) : "invalid pattern";
            result.offset = static_cast<size_t>(errorOffset);
            return result;
        }
        auto compiled = std::make_shared<Compiled>();
        compiled->code.reset(code);
        compiled->context.reset(pcre2_match_context_create(nullptr));
        if (!compiled->context) {
            result.message = "out of memory";
            return result;
        }
        pcre2_set_match_limit(compiled->context.get(), kMatchLimit);
        pcre2_set_depth_limit(compiled->context.get(), kDepthLimit);
        pcre2_set_heap_limit(compiled->context.get(), kHeapLimitKiB);
        result.regex.compiled_ = std::move(compiled);
        result.ok = true;
        return result;
    }

    BoundedRegex::Outcome BoundedRegex::search(std::string_view text) const {
        if (!compiled_) return Outcome::NoMatch;
        const int rc = pcre2_match(compiled_->code.get(), reinterpret_cast<PCRE2_SPTR>(text.data()), text.size(), 0, 0,
                                   threadMatchData(), compiled_->context.get());
        if (rc >= 0) return Outcome::Match;
        switch (rc) {
            case PCRE2_ERROR_NOMATCH: return Outcome::NoMatch;
            case PCRE2_ERROR_MATCHLIMIT:
            case PCRE2_ERROR_DEPTHLIMIT:
            case PCRE2_ERROR_HEAPLIMIT: return Outcome::LimitExceeded;
            default: return Outcome::NoMatch; // any other engine error: never a match
        }
    }
} // namespace filter
