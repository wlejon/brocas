#include "test_harness.h"
#include <brocas/manifest.h>
#include <brocas/store.h>

#include <iostream>

using namespace bro::cas;
using namespace bro::cas::test;

void test_manifest_round_trip() {
    ScopedTempDir src_dir("test_man_src");
    ScopedTempDir dst_dir("test_man_dst");
    ScopedTempDir store_dir("test_man_store");

    Store store(store_dir.path());

    // 1. Create a rich directory tree in src_dir
    src_dir.create_file("small.txt", "Small text file content.");
    src_dir.create_file("empty.txt", "");
    src_dir.create_dir("subdir1");
    src_dir.create_file("subdir1/nested.txt", "Nested file content in subdir1.");
    src_dir.create_dir("subdir1/subsubdir");
    src_dir.create_file("subdir1/subsubdir/deep.txt", "Deeply nested file.");
    src_dir.create_dir("subdir2");

    // Large file (256 KiB) to trigger FastCDC chunking (threshold = 64 KiB)
    src_dir.create_binary_file("large.bin", 256 * 1024, 0x5A);

    // Ingest directory
    IngestOptions ingest_opts;
    ingest_opts.chunk_threshold = 64 * 1024;
    ingest_opts.chunk_options.min_size = 4096;
    ingest_opts.chunk_options.avg_size = 16384;
    ingest_opts.chunk_options.max_size = 65536;

    Hash256 root_hash = ingest_directory(store, src_dir.path(), ingest_opts);
    TEST_CHECK_FALSE(root_hash.is_zero());

    // Ingest again: deterministic hash check!
    Hash256 root_hash2 = ingest_directory(store, src_dir.path(), ingest_opts);
    TEST_CHECK_EQ(root_hash, root_hash2);

    // Checkout directory to dst_dir
    CheckoutOptions checkout_opts;
    CheckoutStats stats = checkout_directory(store, root_hash, dst_dir.path(), checkout_opts);

    TEST_CHECK_EQ(stats.files_created, 5U); // small.txt, empty.txt, nested.txt, deep.txt, large.bin = 5
    // Compare trees byte-exact
    TEST_CHECK_TRUE(ScopedTempDir::compare_trees_byte_exact(src_dir.path(), dst_dir.path()));
}

void test_manifest_diff_and_deduplication() {
    ScopedTempDir src_dir("test_diff_src");
    ScopedTempDir store_dir("test_diff_store");
    Store store(store_dir.path());

    // Create a 1 MiB file
    src_dir.create_binary_file("data.bin", 1024 * 1024, 0x11);
    src_dir.create_file("readme.txt", "Version 1.0");

    IngestOptions opts;
    opts.chunk_threshold = 32 * 1024;
    opts.chunk_options.min_size = 8192;
    opts.chunk_options.avg_size = 32768;
    opts.chunk_options.max_size = 65536;

    Hash256 root1 = ingest_directory(store, src_dir.path(), opts);
    size_t chunk_count1 = store.list_chunks().size();

    // Modify a small portion in the middle of data.bin
    auto data_path = src_dir.path() / "data.bin";
    {
        std::fstream f(data_path, std::ios::in | std::ios::out | std::ios::binary);
        f.seekp(512 * 1024);
        char patch[64];
        std::memset(patch, 0xEE, sizeof(patch));
        f.write(patch, sizeof(patch));
    }
    // Also add a new file and delete readme.txt
    src_dir.create_file("new_file.txt", "Brand new file");
    std::filesystem::remove(src_dir.path() / "readme.txt");

    Hash256 root2 = ingest_directory(store, src_dir.path(), opts);
    size_t chunk_count2 = store.list_chunks().size();

    // Diff root1 and root2
    ManifestDiff diff = diff_manifests(store, root1, root2);
    TEST_CHECK_EQ(diff.added_files.size(), 1U);
    TEST_CHECK_EQ(diff.added_files[0], "new_file.txt");

    TEST_CHECK_EQ(diff.deleted_files.size(), 1U);
    TEST_CHECK_EQ(diff.deleted_files[0], "readme.txt");

    TEST_CHECK_EQ(diff.modified_files.size(), 1U);
    TEST_CHECK_EQ(diff.modified_files[0], "data.bin");

    // Store growth should be tiny: ~1-3 new chunks for data.bin, 1 for new_file.txt, and manifests
    size_t added_chunks = chunk_count2 - chunk_count1;
    std::cout << "Store chunk growth: " << added_chunks << " chunks (from "
              << chunk_count1 << " to " << chunk_count2 << ")" << std::endl;
    TEST_CHECK_TRUE(added_chunks <= 5);
}

int main() {
    test_manifest_round_trip();
    test_manifest_diff_and_deduplication();
    std::cout << "All manifest tests passed!" << std::endl;
    return 0;
}
