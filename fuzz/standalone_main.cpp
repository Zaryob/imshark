// Standalone driver for the fuzz harnesses. It is what the harnesses link against when libFuzzer is not available
// (non-Clang compilers, Apple Clang, MSVC) and what the CTest replay of the seed corpus uses in normal builds.
//
//   harness file-or-directory...        runs every file once (directories are walked recursively, in name order)
//
// Options (arguments starting with '-') are ignored, so the libFuzzer command line works unchanged, except for these,
// which turn the driver into a small coverage-blind mutation fuzzer for machines without libFuzzer (see docs/FUZZING.md):
//
//   -mutate=N            after the replay, run N inputs made by random mutation of the corpus (default: none)
//   -seed=S              seed of the mutation random generator (default: 1); the run is fully reproducible
//   -max_len=L           longest mutant in bytes (default: 65536)
//   -dict=FILE           libFuzzer dictionary (name="value" lines) whose tokens the mutator inserts
//   -artifact_prefix=P   the mutant about to run is first written to P + "last-input": if the process dies in a
//                        sanitizer report or abort(), that file is the reproducer
//
// Exit status: 0 if every input ran, 1 if there was no input or one could not be read (a crash ends the process through
// the sanitizer or abort() as usual).

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>
#include <system_error>
#include <vector>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

namespace {
    constexpr uintmax_t kMaxInputBytes = 64u << 20; // refuse to load something that is clearly not a fuzz input
    using Bytes = std::vector<uint8_t>;

    void collect(const std::filesystem::path &path, std::vector<std::filesystem::path> &out, bool &ok) {
        std::error_code ec;
        if (std::filesystem::is_directory(path, ec)) {
            std::vector<std::filesystem::path> children;
            for (const auto &entry: std::filesystem::directory_iterator(path, ec)) children.push_back(entry.path());
            std::sort(children.begin(), children.end());
            for (const auto &child: children) collect(child, out, ok);
        } else if (std::filesystem::is_regular_file(path, ec)) {
            out.push_back(path);
        } else {
            std::fprintf(stderr, "cannot read %s\n", path.string().c_str());
            ok = false;
        }
    }

    struct Random {
        uint64_t state;
        uint64_t next() {   // xorshift64*
            state ^= state >> 12;
            state ^= state << 25;
            state ^= state >> 27;
            return state * 2685821657736338717ull;
        }
        size_t below(size_t n) { return n ? static_cast<size_t>(next() % n) : 0; }
    };

    /// Tokens of a libFuzzer dictionary: lines of  name="value"  with \xHH, \\ and \" escapes (comments and anything else ignored).
    std::vector<Bytes> loadDictionary(const std::string &path) {
        std::vector<Bytes> tokens;
        std::ifstream file(path);
        std::string line;
        while (std::getline(file, line)) {
            const auto open = line.find('"');
            const auto close = line.rfind('"');
            if (line.empty() || line[0] == '#' || open == std::string::npos || close <= open) continue;
            Bytes token;
            for (size_t i = open + 1; i < close; ++i) {
                if (line[i] == '\\' && i + 1 < close) {
                    ++i;
                    if (line[i] == 'x' && i + 2 < close + 1) {
                        token.push_back(static_cast<uint8_t>(std::strtoul(line.substr(i + 1, 2).c_str(), nullptr, 16)));
                        i += 2;
                    } else {
                        token.push_back(static_cast<uint8_t>(line[i]));
                    }
                } else {
                    token.push_back(static_cast<uint8_t>(line[i]));
                }
            }
            if (!token.empty()) tokens.push_back(std::move(token));
        }
        return tokens;
    }

    void mutate(Bytes &v, Random &rng, const std::vector<Bytes> &pool, const std::vector<Bytes> &dict, size_t maxLen) {
        static const uint8_t interesting8[] = {0, 1, 2, 3, 4, 7, 8, 15, 16, 0x1f, 0x20, 0x3f, 0x40, 0x7e, 0x7f, 0x80, 0x81, 0xfe, 0xff};
        static const uint32_t interesting32[] = {0, 1, 0x7f, 0x80, 0xff, 0x100, 0x7fff, 0x8000, 0xffff, 0x10000, 0x7fffffff, 0x80000000u, 0xffffffffu};
        const int rounds = 1 + static_cast<int>(rng.below(4));
        for (int round = 0; round < rounds; ++round) {
            switch (rng.below(11)) {
                case 0: if (!v.empty()) v[rng.below(v.size())] ^= static_cast<uint8_t>(1u << rng.below(8)); break;
                case 1: if (!v.empty()) v[rng.below(v.size())] = static_cast<uint8_t>(rng.next()); break;
                case 2: if (!v.empty()) v[rng.below(v.size())] = interesting8[rng.below(sizeof(interesting8))]; break;
                case 3: {   // overwrite two or four bytes with an interesting value, either byte order
                    const size_t width = rng.below(2) ? 2 : 4;
                    if (v.size() < width) break;
                    const size_t at = rng.below(v.size() - width + 1);
                    uint32_t value = interesting32[rng.below(sizeof(interesting32) / sizeof(interesting32[0]))];
                    const bool bigEndian = rng.below(2) != 0;
                    for (size_t i = 0; i < width; ++i) v[at + (bigEndian ? width - 1 - i : i)] = static_cast<uint8_t>(value >> (8 * i));
                    break;
                }
                case 4: {   // insert random bytes
                    const size_t n = 1 + rng.below(16);
                    Bytes extra(n);
                    for (auto &b: extra) b = static_cast<uint8_t>(rng.next());
                    v.insert(v.begin() + static_cast<std::ptrdiff_t>(rng.below(v.size() + 1)), extra.begin(), extra.end());
                    break;
                }
                case 5: { if (v.size() <= 1) break;   // delete a range
                    const size_t at = rng.below(v.size());
                    const size_t n = 1 + rng.below(std::min<size_t>(v.size() - at, 32));
                    v.erase(v.begin() + static_cast<std::ptrdiff_t>(at), v.begin() + static_cast<std::ptrdiff_t>(at + n));
                    break;
                }
                case 6: { if (v.empty()) break;   // duplicate a range
                    const size_t at = rng.below(v.size());
                    const size_t n = 1 + rng.below(std::min<size_t>(v.size() - at, 64));
                    const Bytes copy(v.begin() + static_cast<std::ptrdiff_t>(at), v.begin() + static_cast<std::ptrdiff_t>(at + n));
                    v.insert(v.begin() + static_cast<std::ptrdiff_t>(rng.below(v.size() + 1)), copy.begin(), copy.end());
                    break;
                }
                case 7: { if (dict.empty()) break;   // insert or overwrite with a dictionary token
                    const Bytes &token = dict[rng.below(dict.size())];
                    if (!v.empty() && rng.below(2)) {
                        const size_t at = rng.below(v.size());
                        for (size_t i = 0; i < token.size() && at + i < v.size(); ++i) v[at + i] = token[i];
                    } else {
                        v.insert(v.begin() + static_cast<std::ptrdiff_t>(rng.below(v.size() + 1)), token.begin(), token.end());
                    }
                    break;
                }
                case 8: { if (pool.empty() || v.empty()) break;   // splice: the head of this input, the tail of another
                    const Bytes &other = pool[rng.below(pool.size())];
                    if (other.empty()) break;
                    v.resize(rng.below(v.size() + 1));
                    v.insert(v.end(), other.begin() + static_cast<std::ptrdiff_t>(rng.below(other.size())), other.end());
                    break;
                }
                case 9: v.resize(rng.below(v.size() + 1)); break;   // truncate
                default: if (!v.empty()) {      // arithmetic on one byte
                    uint8_t &b = v[rng.below(v.size())];
                    b = static_cast<uint8_t>(b + static_cast<int>(rng.below(33)) - 16);
                }
            }
        }
        if (v.size() > maxLen) v.resize(maxLen);
    }

    bool writeFile(const std::string &path, const Bytes &bytes) {
        std::ofstream out(path, std::ios::binary | std::ios::trunc);
        if (!bytes.empty()) out.write(reinterpret_cast<const char *>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
        return out.good();
    }
} // namespace

int main(int argc, char **argv) {
    std::vector<std::filesystem::path> inputs;
    bool ok = true;
    uint64_t mutations = 0, seed = 1, maxLen = 65536;
    std::string dictPath, artifactPrefix;
    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];
        if (arg.rfind("-mutate=", 0) == 0) mutations = std::strtoull(arg.c_str() + 8, nullptr, 10);
        else if (arg.rfind("-seed=", 0) == 0) seed = std::strtoull(arg.c_str() + 6, nullptr, 10);
        else if (arg.rfind("-max_len=", 0) == 0) maxLen = std::strtoull(arg.c_str() + 9, nullptr, 10);
        else if (arg.rfind("-dict=", 0) == 0) dictPath = arg.substr(6);
        else if (arg.rfind("-artifact_prefix=", 0) == 0) artifactPrefix = arg.substr(17);
        else if (arg[0] != '-') collect(std::filesystem::path(arg), inputs, ok);
    }
    if (inputs.empty()) {
        std::fprintf(stderr, "usage: %s file-or-directory...\n", argc > 0 ? argv[0] : "fuzz-harness");
        return 1;
    }
    size_t executed = 0;
    std::vector<Bytes> pool;
    for (const auto &input: inputs) {
        std::error_code ec;
        const auto size = std::filesystem::file_size(input, ec);
        if (ec || size > kMaxInputBytes) {
            std::fprintf(stderr, "skipping %s: unreadable or larger than %ju bytes\n", input.string().c_str(),
                         static_cast<uintmax_t>(kMaxInputBytes));
            ok = false;
            continue;
        }
        std::ifstream file(input, std::ios::binary);
        Bytes bytes((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
        LLVMFuzzerTestOneInput(bytes.data(), bytes.size());
        ++executed;
        if (mutations && bytes.size() <= maxLen) pool.push_back(std::move(bytes));
    }
    std::printf("Executed %zu inputs\n", executed);

    if (mutations && !pool.empty()) {
        const auto dict = dictPath.empty() ? std::vector<Bytes>() : loadDictionary(dictPath);
        const std::string lastInput = artifactPrefix + "last-input";
        Random rng{seed * 0x9E3779B97F4A7C15ull + 1};
        for (uint64_t n = 0; n < mutations; ++n) {
            Bytes mutant = pool[rng.below(pool.size())];
            mutate(mutant, rng, pool, dict, static_cast<size_t>(maxLen));
            if (!writeFile(lastInput, mutant)) std::fprintf(stderr, "cannot write %s\n", lastInput.c_str());
            LLVMFuzzerTestOneInput(mutant.data(), mutant.size());
            ++executed;
            if (n % 16 == 0 && pool.size() < 4096) pool.push_back(std::move(mutant));   // random walk away from the seeds
        }
        std::error_code ec;
        std::filesystem::remove(std::filesystem::path(lastInput), ec);
        std::printf("Executed %zu inputs (%llu mutated)\n", executed, static_cast<unsigned long long>(mutations));
    }
    return ok ? 0 : 1;
}
