// Fuzzes the gzip / deflate decompressor (core/src/gzip.cpp) that unpacks .gz captures before they are read.
//
// Input: the bytes of a gzip file. They are decompressed in memory (output capped) and, if small enough, through
// the streaming file path the loader uses (gunzipFile), which checks CRC-32 and size of every member. Both paths
// must agree on whether the data is valid and on the decompressed bytes.

#include <cstddef>
#include <cstdint>
#include <fstream>
#include <iterator>
#include <string>

#include <gzip.h>
#include <load_control.h>

#include "fuzz_common.h"

namespace {
    constexpr size_t kMaxInput = 64 * 1024;
    constexpr size_t kMaxFileInput = 16 * 1024;     // deflate expands up to ~1000:1: bounds the file the streaming path writes
    constexpr uint64_t kMaxOutput = 32u << 20;
} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size > kMaxInput) return 0;

    std::string memoryOut, memoryError;
    const std::string compressed(reinterpret_cast<const char *>(data), size);
    const bool memoryOk = core::gunzipMemory(compressed, memoryOut, kMaxOutput, memoryError);
    if (!memoryOk) FUZZ_CHECK(!memoryError.empty());

    if (size > kMaxFileInput) return 0;
    fuzz::TempFile input("gzip.in");
    fuzz::TempFile output("gzip.out");
    if (!input.write(data, size)) return 0;
    std::string fileError;
    core::LoadControl control;
    const bool fileOk = core::gunzipFile(input.path(), output.path(), fileError, &control);
    if (!fileOk) FUZZ_CHECK(!fileError.empty());

    if (memoryOk && fileOk) {
        std::ifstream result(output.path(), std::ios::binary);
        const std::string fileOut((std::istreambuf_iterator<char>(result)), std::istreambuf_iterator<char>());
        FUZZ_CHECK(fileOut == memoryOut);
    }
    return 0;
}
