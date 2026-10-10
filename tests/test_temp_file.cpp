#include <gtest/gtest.h>

#include <cerrno>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <set>
#include <thread>
#include <vector>

#include <core.h>
#include <temp_file.h>

#ifndef _WIN32
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace {
    std::filesystem::path fsPath(const std::string &p) { return core::pathFromUtf8(p); }
} // namespace

TEST(TempFile, CreatesAnEmptyFileInsideThePrivateDirectory) {
    std::string error;
    const std::string path = core::createTempFile(".cap", &error);
    ASSERT_FALSE(path.empty()) << error;
    EXPECT_TRUE(std::filesystem::is_regular_file(fsPath(path)));
    EXPECT_EQ(std::filesystem::file_size(fsPath(path)), 0u);
    EXPECT_EQ(fsPath(path).parent_path(), fsPath(core::privateTempDir()));
    EXPECT_EQ(fsPath(path).extension(), ".cap");
    std::ofstream out(fsPath(path), std::ios::binary | std::ios::trunc);   // the documented reopen
    out << "x";
    out.close();
    EXPECT_EQ(std::filesystem::file_size(fsPath(path)), 1u);
    std::filesystem::remove(fsPath(path));
}

TEST(TempFile, RejectsASuffixThatEscapesTheDirectory) {
    std::string error;
    EXPECT_TRUE(core::createTempFile("/../evil", &error).empty());
    EXPECT_FALSE(error.empty());
}

#ifndef _WIN32
TEST(TempFile, FileIsOwnerOnlyInsideAnOwnerOnlyDirectory) {
    const std::string path = core::createTempFile(".pcap");
    ASSERT_FALSE(path.empty());
    struct stat st {};
    ASSERT_EQ(::stat(path.c_str(), &st), 0);
    EXPECT_EQ(st.st_mode & 0777, 0600u);
    ASSERT_EQ(::stat(core::privateTempDir().c_str(), &st), 0);
    EXPECT_EQ(st.st_mode & 0777, 0700u);
    EXPECT_EQ(st.st_uid, ::geteuid());
    std::filesystem::remove(fsPath(path));
}

TEST(TempFile, PlantedEntriesInTheDirectoryAreNeverTouched) {
    // Names are random, so a symlink cannot be planted at the exact candidate; check that planted entries survive
    // many creations untouched (the victim behind the link keeps its content).
    const auto dir = fsPath(core::privateTempDir());
    const auto victim = dir / "victim.txt";
    { std::ofstream v(victim); v << "precious"; }
    const auto link = dir / "link_to_victim";
    std::filesystem::create_symlink(victim, link);
    std::vector<std::string> made;
    for (int i = 0; i < 50; ++i) {
        const std::string p = core::createTempFile(".cap");
        ASSERT_FALSE(p.empty());
        made.push_back(p);
    }
    std::ifstream v(victim);
    const std::string text((std::istreambuf_iterator<char>(v)), std::istreambuf_iterator<char>());
    EXPECT_EQ(text, "precious");
    for (const auto &p: made) {
        EXPECT_FALSE(std::filesystem::is_symlink(fsPath(p)));
        std::filesystem::remove(fsPath(p));
    }
    std::filesystem::remove(link);
    std::filesystem::remove(victim);
}

TEST(TempFile, ExclusiveNoFollowOpenRefusesASymlink) {
    // exactly the flags createTempFile uses, against a planted symlink: the primitive the design relies on
    const auto dir = fsPath(core::privateTempDir());
    const auto victim = dir / "victim2.txt";
    { std::ofstream v(victim); v << "precious"; }
    const auto link = dir / "planted";
    std::filesystem::create_symlink(victim, link);
    errno = 0;
    const int fd = ::open(link.c_str(), O_CREAT | O_EXCL | O_WRONLY | O_NOFOLLOW | O_CLOEXEC, 0600);
    EXPECT_LT(fd, 0);
    EXPECT_EQ(errno, EEXIST);
    if (fd >= 0) ::close(fd);
    EXPECT_EQ(std::filesystem::file_size(victim), 8u);
    std::filesystem::remove(link);
    std::filesystem::remove(victim);
}
#endif

TEST(TempFile, NamesAreUniqueAcrossThreads) {
    constexpr int kThreads = 8, kPerThread = 50;
    std::vector<std::vector<std::string>> results(kThreads);
    std::vector<std::thread> threads;
    for (int t = 0; t < kThreads; ++t) {
        threads.emplace_back([&, t] {
            for (int i = 0; i < kPerThread; ++i) results[t].push_back(core::createTempFile(".tmp"));
        });
    }
    for (auto &th: threads) th.join();
    std::set<std::string> unique;
    for (const auto &r: results) {
        for (const auto &p: r) {
            ASSERT_FALSE(p.empty());
            unique.insert(p);
            std::filesystem::remove(fsPath(p));
        }
    }
    EXPECT_EQ(unique.size(), static_cast<size_t>(kThreads * kPerThread));
}

TEST(TempFile, RemovingTheFilesLeavesTheDirectoryUsable) {
    const std::string a = core::createTempFile(".a");
    ASSERT_FALSE(a.empty());
    std::filesystem::remove(fsPath(a));
    EXPECT_FALSE(std::filesystem::exists(fsPath(a)));
    EXPECT_TRUE(std::filesystem::is_directory(fsPath(core::privateTempDir())));
}
