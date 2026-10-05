#include "test_harness.h"
#include <brocas/fastcdc.h>

#include <numeric>
#include <sstream>
#include <unordered_set>

using namespace bro::cas;
using namespace bro::cas::test;

void test_fastcdc_bounds() {
    ChunkOptions options;
    options.min_size = 4096;
    options.avg_size = 16384;
    options.max_size = 65536;

    // Create 512 KiB pseudo-random buffer
    std::vector<uint8_t> data(512 * 1024);
    uint32_t state = 123456789;
    for (size_t i = 0; i < data.size(); ++i) {
        state = state * 1664525 + 1013904223;
        data[i] = static_cast<uint8_t>(state >> 24);
    }

    auto chunks = chunk_buffer(data, options);
    TEST_CHECK_FALSE(chunks.empty());

    uint64_t total_size = 0;
    for (size_t i = 0; i < chunks.size(); ++i) {
        const auto& c = chunks[i];
        TEST_CHECK_EQ(c.offset, total_size);

        if (i + 1 < chunks.size()) {
            TEST_CHECK_TRUE(c.size >= options.min_size);
            TEST_CHECK_TRUE(c.size <= options.max_size);
        } else {
            // Last chunk can be smaller than min_size
            TEST_CHECK_TRUE(c.size <= options.max_size);
        }

        // Verify chunk hash
        Hash256 expected_hash = Hasher::hash(data.data() + c.offset, c.size);
        TEST_CHECK_EQ(c.hash, expected_hash);

        total_size += c.size;
    }

    TEST_CHECK_EQ(total_size, static_cast<uint64_t>(data.size()));
}

void test_fastcdc_stream_consistency() {
    ChunkOptions options;
    options.min_size = 4096;
    options.avg_size = 16384;
    options.max_size = 65536;

    std::vector<uint8_t> data(256 * 1024);
    for (size_t i = 0; i < data.size(); ++i) {
        data[i] = static_cast<uint8_t>((i * 37) ^ (i >> 5));
    }

    auto buffer_chunks = chunk_buffer(data, options);

    // Stream with arbitrary small read chunks
    std::string str_data(reinterpret_cast<const char*>(data.data()), data.size());
    std::istringstream iss(str_data);

    std::vector<ChunkInfo> stream_chunks;
    chunk_stream(iss, [&](const ChunkInfo& info, std::span<const uint8_t>) {
        stream_chunks.push_back(info);
    }, options);

    TEST_CHECK_EQ(buffer_chunks.size(), stream_chunks.size());
    for (size_t i = 0; i < buffer_chunks.size(); ++i) {
        TEST_CHECK_EQ(buffer_chunks[i].offset, stream_chunks[i].offset);
        TEST_CHECK_EQ(buffer_chunks[i].size, stream_chunks[i].size);
        TEST_CHECK_EQ(buffer_chunks[i].hash, stream_chunks[i].hash);
    }
}

void test_fastcdc_deduplication() {
    ChunkOptions options;
    options.min_size = 8 * 1024;    // 8 KiB
    options.avg_size = 32 * 1024;   // 32 KiB
    options.max_size = 128 * 1024;  // 128 KiB

    // 2 MiB file
    const size_t file_size = 2 * 1024 * 1024;
    std::vector<uint8_t> original(file_size);
    uint32_t state = 987654321;
    for (size_t i = 0; i < file_size; ++i) {
        state = state * 1103515245 + 12345;
        original[i] = static_cast<uint8_t>(state >> 16);
    }

    auto chunks_orig = chunk_buffer(original, options);
    TEST_CHECK_TRUE(chunks_orig.size() >= 30); // ~60 chunks expected

    std::unordered_set<Hash256> orig_hashes;
    for (const auto& c : chunks_orig) {
        orig_hashes.insert(c.hash);
    }

    // Edit 64 bytes right in the middle (at 1 MiB)
    std::vector<uint8_t> modified = original;
    for (size_t i = 0; i < 64; ++i) {
        modified[1024 * 1024 + i] ^= 0xFF;
    }

    auto chunks_mod = chunk_buffer(modified, options);

    size_t shared_count = 0;
    for (const auto& c : chunks_mod) {
        if (orig_hashes.contains(c.hash)) {
            shared_count++;
        }
    }

    double shared_ratio = static_cast<double>(shared_count) / static_cast<double>(chunks_mod.size());
    std::cout << "FastCDC deduplication: " << shared_count << " / " << chunks_mod.size()
              << " chunks shared (" << (shared_ratio * 100.0) << "%)" << std::endl;

    // Requirement: >90% of chunks shared after small edit
    TEST_CHECK_TRUE(shared_ratio >= 0.90);
}

void test_fastcdc_edge_cases() {
    ChunkOptions options;
    options.min_size = 16384;
    options.avg_size = 65536;
    options.max_size = 262144;

    // Empty buffer
    auto empty_chunks = chunk_buffer(nullptr, 0, options);
    TEST_CHECK_TRUE(empty_chunks.empty());

    // Very small buffer (smaller than min_size)
    std::vector<uint8_t> small_data = {1, 2, 3, 4, 5, 6, 7, 8};
    auto small_chunks = chunk_buffer(small_data, options);
    TEST_CHECK_EQ(small_chunks.size(), 1U);
    TEST_CHECK_EQ(small_chunks[0].size, 8U);
    TEST_CHECK_EQ(small_chunks[0].hash, Hasher::hash(small_data));
}

int main() {
    test_fastcdc_bounds();
    test_fastcdc_stream_consistency();
    test_fastcdc_deduplication();
    test_fastcdc_edge_cases();
    std::cout << "All FastCDC tests passed!" << std::endl;
    return 0;
}
