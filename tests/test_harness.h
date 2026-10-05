#pragma once

#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <random>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>
#include <cstring>

#define TEST_CHECK(cond) \
    do { \
        if (!(cond)) { \
            std::cerr << "CHECK FAILED: " #cond " at " << __FILE__ << ":" << __LINE__ << std::endl; \
            std::exit(1); \
        } \
    } while (0)

#define TEST_CHECK_EQ(a, b) \
    do { \
        const auto& _val_a = (a); \
        const auto& _val_b = (b); \
        if (!(_val_a == _val_b)) { \
            std::cerr << "CHECK FAILED: " #a " == " #b " (" << _val_a << " != " << _val_b << ") at " << __FILE__ << ":" << __LINE__ << std::endl; \
            std::exit(1); \
        } \
    } while (0)

#define TEST_CHECK_NE(a, b) \
    do { \
        const auto& _val_a = (a); \
        const auto& _val_b = (b); \
        if (_val_a == _val_b) { \
            std::cerr << "CHECK FAILED: " #a " != " #b " (" << _val_a << " == " << _val_b << ") at " << __FILE__ << ":" << __LINE__ << std::endl; \
            std::exit(1); \
        } \
    } while (0)

#define TEST_CHECK_TRUE(cond) TEST_CHECK(cond)
#define TEST_CHECK_FALSE(cond) TEST_CHECK(!(cond))

#define TEST_FAIL(msg) \
    do { \
        std::cerr << "TEST FAILED: " << msg << " at " << __FILE__ << ":" << __LINE__ << std::endl; \
        std::exit(1); \
    } while (0)

namespace bro::cas::test {

class ScopedTempDir {
public:
    ScopedTempDir(std::string_view prefix = "brocas_test") {
        auto now = std::chrono::steady_clock::now().time_since_epoch().count();
        std::random_device rd;
        uint32_t rnd = rd();
        path_ = std::filesystem::temp_directory_path() /
                (std::string(prefix) + "_" + std::to_string(now) + "_" + std::to_string(rnd));
        std::error_code ec;
        std::filesystem::create_directories(path_, ec);
    }

    ~ScopedTempDir() {
        clean();
    }

    ScopedTempDir(const ScopedTempDir&) = delete;
    ScopedTempDir& operator=(const ScopedTempDir&) = delete;

    ScopedTempDir(ScopedTempDir&& other) noexcept : path_(std::move(other.path_)) {}
    ScopedTempDir& operator=(ScopedTempDir&& other) noexcept {
        if (this != &other) {
            clean();
            path_ = std::move(other.path_);
        }
        return *this;
    }

    const std::filesystem::path& path() const noexcept { return path_; }

    void clean() {
        if (!path_.empty()) {
            std::error_code ec;
            std::filesystem::remove_all(path_, ec);
            path_.clear();
        }
    }

    std::filesystem::path create_dir(const std::filesystem::path& rel) {
        auto p = path_ / rel;
        std::error_code ec;
        std::filesystem::create_directories(p, ec);
        return p;
    }

    std::filesystem::path create_file(const std::filesystem::path& rel, std::string_view content) {
        auto p = path_ / rel;
        std::error_code ec;
        std::filesystem::create_directories(p.parent_path(), ec);
        std::ofstream f(p, std::ios::binary | std::ios::trunc);
        f.write(content.data(), static_cast<std::streamsize>(content.size()));
        return p;
    }

    std::filesystem::path create_binary_file(const std::filesystem::path& rel, size_t size, uint8_t seed = 0x42) {
        auto p = path_ / rel;
        std::error_code ec;
        std::filesystem::create_directories(p.parent_path(), ec);
        std::ofstream f(p, std::ios::binary | std::ios::trunc);

        std::vector<uint8_t> buffer(65536);
        size_t written = 0;
        uint64_t state = static_cast<uint64_t>(seed) * 1000000007ULL + 12345;
        while (written < size) {
            size_t to_write = std::min(buffer.size(), size - written);
            for (size_t i = 0; i < to_write; ++i) {
                state = state * 6364136223846793005ULL + 1442695040888963407ULL;
                buffer[i] = static_cast<uint8_t>(state >> 32);
            }
            f.write(reinterpret_cast<const char*>(buffer.data()), static_cast<std::streamsize>(to_write));
            written += to_write;
        }
        return p;
    }

    std::string read_file(const std::filesystem::path& rel) {
        auto p = path_ / rel;
        std::ifstream f(p, std::ios::binary);
        return std::string((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
    }

    static bool compare_files_byte_exact(const std::filesystem::path& p1, const std::filesystem::path& p2) {
        std::error_code ec;
        if (std::filesystem::file_size(p1, ec) != std::filesystem::file_size(p2, ec)) {
            return false;
        }

        std::ifstream f1(p1, std::ios::binary);
        std::ifstream f2(p2, std::ios::binary);
        if (!f1.is_open() || !f2.is_open()) return false;

        std::vector<char> buf1(65536);
        std::vector<char> buf2(65536);
        while (f1.good() && f2.good()) {
            f1.read(buf1.data(), buf1.size());
            f2.read(buf2.data(), buf2.size());
            if (f1.gcount() != f2.gcount()) return false;
            if (f1.gcount() == 0) break;
            if (std::memcmp(buf1.data(), buf2.data(), static_cast<size_t>(f1.gcount())) != 0) {
                return false;
            }
        }
        return f1.eof() && f2.eof();
    }

    static bool compare_trees_byte_exact(const std::filesystem::path& d1, const std::filesystem::path& d2) {
        std::error_code ec;
        for (const auto& entry1 : std::filesystem::recursive_directory_iterator(d1, ec)) {
            if (ec) return false;
            auto rel = std::filesystem::relative(entry1.path(), d1);
            auto target = d2 / rel;

            if (!std::filesystem::exists(target, ec)) {
                return false;
            }

            if (entry1.is_directory(ec)) {
                if (!std::filesystem::is_directory(target, ec)) return false;
            } else if (entry1.is_regular_file(ec)) {
                if (!std::filesystem::is_regular_file(target, ec)) return false;
                if (!compare_files_byte_exact(entry1.path(), target)) return false;
            } else if (entry1.is_symlink(ec)) {
                if (!std::filesystem::is_symlink(target, ec)) return false;
                auto t1 = std::filesystem::read_symlink(entry1.path(), ec);
                auto t2 = std::filesystem::read_symlink(target, ec);
                if (t1 != t2) return false;
            }
        }

        // Verify no extra files in d2
        for (const auto& entry2 : std::filesystem::recursive_directory_iterator(d2, ec)) {
            if (ec) return false;
            auto rel = std::filesystem::relative(entry2.path(), d2);
            auto source = d1 / rel;
            if (!std::filesystem::exists(source, ec)) {
                return false;
            }
        }

        return true;
    }

private:
    std::filesystem::path path_;
};

} // namespace bro::cas::test
