#include "test_harness.h"
#include <brocas/hash.h>

#include <unordered_map>
#include <unordered_set>

using namespace bro::cas;
using namespace bro::cas::test;

void test_blake3_vectors() {
    // Official BLAKE3 test vector for empty input
    Hash256 h_empty = Hasher::hash("");
    std::string hex_empty = h_empty.to_hex();
    TEST_CHECK_EQ(hex_empty, "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262");

    // Test vector round trip
    auto parsed = Hash256::from_hex(hex_empty);
    TEST_CHECK_TRUE(parsed.has_value());
    TEST_CHECK_EQ(*parsed, h_empty);

    // Case insensitivity
    std::string upper_hex = "AF1349B9F5F9A1A6A0404DEA36DCC9499BCB25C9ADC112B7CC9A93CAE41F3262";
    auto parsed_upper = Hash256::from_hex(upper_hex);
    TEST_CHECK_TRUE(parsed_upper.has_value());
    TEST_CHECK_EQ(*parsed_upper, h_empty);

    // Invalid hex strings
    TEST_CHECK_FALSE(Hash256::from_hex("").has_value());
    TEST_CHECK_FALSE(Hash256::from_hex("af13").has_value());
    TEST_CHECK_FALSE(Hash256::from_hex("zzzz49b4f00a0c9382ec303ddcb747d14c6c5ac7c2e477eec82a571ed52439b2").has_value());
}

void test_hash_properties() {
    Hash256 zero = Hash256::zero();
    TEST_CHECK_TRUE(zero.is_zero());

    Hash256 h1 = Hasher::hash("hello");
    TEST_CHECK_FALSE(h1.is_zero());
    Hash256 h2 = Hasher::hash("world");
    Hash256 h3 = Hasher::hash("hello");

    TEST_CHECK_EQ(h1, h3);
    TEST_CHECK_NE(h1, h2);
    TEST_CHECK_TRUE((h1 < h2) || (h2 < h1));

    // Hash map and set
    std::unordered_set<Hash256> set;
    set.insert(h1);
    set.insert(h2);
    TEST_CHECK_EQ(set.size(), 2U);
    TEST_CHECK_TRUE(set.contains(h3));

    std::unordered_map<Hash256, std::string> map;
    map[h1] = "hello_val";
    map[h2] = "world_val";
    TEST_CHECK_EQ(map[h3], "hello_val");
}

void test_incremental_hashing() {
    std::string full_data(100000, 'x');
    for (size_t i = 0; i < full_data.size(); ++i) {
        full_data[i] = static_cast<char>((i % 251) + 1);
    }

    Hash256 one_shot = Hasher::hash(full_data);

    Hasher hasher;
    size_t chunk_size = 377;
    for (size_t offset = 0; offset < full_data.size(); offset += chunk_size) {
        size_t len = std::min(chunk_size, full_data.size() - offset);
        hasher.update(full_data.data() + offset, len);
    }
    Hash256 incremental = hasher.finalize();

    TEST_CHECK_EQ(one_shot, incremental);

    // Test reset
    hasher.reset();
    hasher.update(full_data);
    TEST_CHECK_EQ(hasher.finalize(), one_shot);
}

void test_file_hashing() {
    ScopedTempDir temp("test_hash_file");
    std::string test_str = "Content-addressed storage library in C++20 for bro desktop runtime.";
    auto file_path = temp.create_file("test.txt", test_str);

    auto file_hash = Hasher::hash_file(file_path);
    TEST_CHECK_TRUE(file_hash.has_value());
    TEST_CHECK_EQ(*file_hash, Hasher::hash(test_str));

    // Non-existent file
    auto non_existent = Hasher::hash_file(temp.path() / "not_there.txt");
    TEST_CHECK_FALSE(non_existent.has_value());
}

int main() {
    test_blake3_vectors();
    test_hash_properties();
    test_incremental_hashing();
    test_file_hashing();
    std::cout << "All hash tests passed!" << std::endl;
    return 0;
}
