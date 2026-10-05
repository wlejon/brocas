#include "test_harness.h"
#include <brocas/hash.h>

#include <chrono>
#include <fstream>
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

static std::string bytes_to_hex(const uint8_t* data, size_t len) {
    static const char hex_chars[] = "0123456789abcdef";
    std::string res;
    res.reserve(len * 2);
    for (size_t i = 0; i < len; ++i) {
        res.push_back(hex_chars[(data[i] >> 4) & 0x0F]);
        res.push_back(hex_chars[data[i] & 0x0F]);
    }
    return res;
}

struct TestCase {
    size_t input_len = 0;
    std::string hash;
    std::string keyed_hash;
    std::string derive_key;
};

void test_all_official_vectors() {
    std::filesystem::path vec_path;
#ifdef BROCAS_TEST_DIR
    vec_path = std::filesystem::path(BROCAS_TEST_DIR) / "test_vectors.json";
#else
    vec_path = "tests/test_vectors.json";
#endif
    if (!std::filesystem::exists(vec_path)) {
        vec_path = "../tests/test_vectors.json";
    }

    std::ifstream file(vec_path);
    TEST_CHECK_TRUE(file.is_open());

    std::string content((std::istreambuf_iterator<char>(file)),
                         std::istreambuf_iterator<char>());
    TEST_CHECK_FALSE(content.empty());

    // Extract key and context_string
    auto find_str = [&](std::string_view key_name) -> std::string {
        std::string pattern = "\"" + std::string(key_name) + "\": \"";
        auto pos = content.find(pattern);
        if (pos == std::string::npos) return "";
        pos += pattern.size();
        auto end_pos = content.find('"', pos);
        return content.substr(pos, end_pos - pos);
    };

    std::string key = find_str("key");
    std::string context_string = find_str("context_string");
    TEST_CHECK_EQ(key, "whats the Elvish word for friend");
    TEST_CHECK_EQ(context_string, "BLAKE3 2019-12-27 16:29:52 test vectors context");

    // Parse cases
    std::vector<TestCase> cases;
    size_t pos = content.find("\"cases\":");
    TEST_CHECK_TRUE(pos != std::string::npos);

    while (true) {
        pos = content.find('{', pos);
        if (pos == std::string::npos) break;
        size_t end_case = content.find('}', pos);
        if (end_case == std::string::npos) break;

        std::string case_str = content.substr(pos, end_case - pos + 1);

        auto extract_val = [&](std::string_view k) -> std::string {
            std::string pat = "\"" + std::string(k) + "\":";
            auto kp = case_str.find(pat);
            if (kp == std::string::npos) return "";
            kp += pat.size();
            while (kp < case_str.size() && (case_str[kp] == ' ' || case_str[kp] == '\t' || case_str[kp] == '\n' || case_str[kp] == '\r')) {
                kp++;
            }
            if (kp < case_str.size() && case_str[kp] == '"') {
                kp++;
                auto ep = case_str.find('"', kp);
                return case_str.substr(kp, ep - kp);
            } else {
                auto ep = case_str.find_first_of(",}\r\n", kp);
                return case_str.substr(kp, ep - kp);
            }
        };

        std::string input_len_str = extract_val("input_len");
        if (!input_len_str.empty()) {
            TestCase tc;
            tc.input_len = std::stoull(input_len_str);
            tc.hash = extract_val("hash");
            tc.keyed_hash = extract_val("keyed_hash");
            tc.derive_key = extract_val("derive_key");
            cases.push_back(std::move(tc));
        }

        pos = end_case + 1;
    }

    TEST_CHECK_EQ(cases.size(), 35U);

    std::cout << "Running official BLAKE3 test vectors (35 cases)..." << std::endl;

    for (const auto& tc : cases) {
        std::vector<uint8_t> input(tc.input_len);
        for (size_t i = 0; i < tc.input_len; ++i) {
            input[i] = static_cast<uint8_t>(i % 251);
        }

        size_t xof_len = tc.hash.size() / 2;
        std::vector<uint8_t> xof_out(xof_len);

        // 1. Regular Hash
        Hash256 h_default = Hasher::hash(input);
        TEST_CHECK_EQ(h_default.to_hex(), tc.hash.substr(0, 64));

        Hasher h;
        h.update(input);
        h.finalize_xof(xof_out.data(), xof_len);
        TEST_CHECK_EQ(bytes_to_hex(xof_out.data(), xof_len), tc.hash);

        // 2. Keyed Hash
        auto key_bytes = reinterpret_cast<const uint8_t*>(key.data());
        Hasher h_keyed = Hasher::new_keyed(key_bytes);
        h_keyed.update(input);
        TEST_CHECK_EQ(h_keyed.finalize().to_hex(), tc.keyed_hash.substr(0, 64));

        Hasher h_keyed_xof = Hasher::new_keyed(key_bytes);
        h_keyed_xof.update(input);
        h_keyed_xof.finalize_xof(xof_out.data(), xof_len);
        TEST_CHECK_EQ(bytes_to_hex(xof_out.data(), xof_len), tc.keyed_hash);

        // 3. Derive Key
        Hasher h_dk = Hasher::new_derive_key(context_string);
        h_dk.update(input);
        TEST_CHECK_EQ(h_dk.finalize().to_hex(), tc.derive_key.substr(0, 64));

        Hasher h_dk_xof = Hasher::new_derive_key(context_string);
        h_dk_xof.update(input);
        h_dk_xof.finalize_xof(xof_out.data(), xof_len);
        TEST_CHECK_EQ(bytes_to_hex(xof_out.data(), xof_len), tc.derive_key);
    }
}

void test_simd_and_throughput() {
    size_t simd_degree = blake3_simd_degree();
    std::cout << "BLAKE3 SIMD degree: " << simd_degree << " (";
#if defined(__x86_64__) || defined(_M_X64)
    std::cout << "x86_64";
#elif defined(__aarch64__) || defined(_M_ARM64)
    std::cout << "ARM64";
#else
    std::cout << "portable";
#endif
    std::cout << ")" << std::endl;

    TEST_CHECK_TRUE(simd_degree >= 1);
#if defined(__x86_64__) || defined(_M_X64)
    // On x86_64 with SSE4.1/AVX2/AVX512, degree is at least 4
    TEST_CHECK_TRUE(simd_degree >= 4);
#elif defined(__aarch64__) || defined(_M_ARM64)
    // On ARM64 with NEON, degree is 4
    TEST_CHECK_TRUE(simd_degree >= 4);
#endif

    const size_t bench_size = 64 * 1024 * 1024; // 64 MB
    std::vector<uint8_t> bench_data(bench_size);
    for (size_t i = 0; i < bench_size; i += 4096) {
        bench_data[i] = static_cast<uint8_t>(i & 0xFF);
    }

    // Warmup
    volatile auto w = Hasher::hash(bench_data);
    (void)w;

    auto t0 = std::chrono::high_resolution_clock::now();
    Hash256 h = Hasher::hash(bench_data);
    auto t1 = std::chrono::high_resolution_clock::now();

    double elapsed_sec = std::chrono::duration<double>(t1 - t0).count();
    double mb_per_sec = (bench_size / (1024.0 * 1024.0)) / elapsed_sec;
    double gb_per_sec = (bench_size / (1000.0 * 1000.0 * 1000.0)) / elapsed_sec;

    std::cout << "BLAKE3 throughput: " << mb_per_sec << " MB/s ("
              << gb_per_sec << " GB/s), elapsed: "
              << (elapsed_sec * 1000.0) << " ms for 64 MB (hash: "
              << h.to_hex().substr(0, 16) << "...)" << std::endl;

    // Minimum throughput requirement with SIMD: >= 500 MB/s. Only meaningful
    // for optimized builds: unoptimized intrinsics kernels run at a fraction
    // of that (about 300 MB/s for GCC 12 -O0 with AVX-512).
#ifdef NDEBUG
    TEST_CHECK_TRUE(mb_per_sec >= 500.0);
#else
    std::cout << "Throughput floor not enforced in an unoptimized build" << std::endl;
#endif
}

int main() {
    test_blake3_vectors();
    test_all_official_vectors();
    test_hash_properties();
    test_incremental_hashing();
    test_file_hashing();
    test_simd_and_throughput();
    std::cout << "All hash tests passed!" << std::endl;
    return 0;
}

