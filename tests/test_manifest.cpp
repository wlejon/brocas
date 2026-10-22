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

void test_manifest_diff_recursive_dirs_and_symlinks() {
    ScopedTempDir dir1("test_diff_rec_1");
    ScopedTempDir dir2("test_diff_rec_2");
    ScopedTempDir store_dir("test_diff_rec_store");
    Store store(store_dir.path());

    // Tree 1:
    // - old_dir/a.txt
    // - old_dir/nested/b.txt
    // - dir_to_file/inside.txt
    // - file_to_dir (regular file)
    // - link1 -> old_dir/a.txt
    dir1.create_file("old_dir/a.txt", "a");
    dir1.create_file("old_dir/nested/b.txt", "b");
    dir1.create_file("dir_to_file/inside.txt", "inside");
    dir1.create_file("file_to_dir", "plain file");
    std::filesystem::create_symlink("old_dir/a.txt", dir1.path() / "link1");

    // Tree 2:
    // - new_dir/c.txt
    // - new_dir/sub/d.txt
    // - dir_to_file (regular file)
    // - file_to_dir/child.txt
    // - link1 -> new_dir/c.txt
    // - link2 -> dir_to_file
    dir2.create_file("new_dir/c.txt", "c");
    dir2.create_file("new_dir/sub/d.txt", "d");
    dir2.create_file("dir_to_file", "now a regular file");
    dir2.create_file("file_to_dir/child.txt", "child content");
    std::filesystem::create_symlink("new_dir/c.txt", dir2.path() / "link1");
    std::filesystem::create_symlink("dir_to_file", dir2.path() / "link2");

    Hash256 root1 = ingest_directory(store, dir1.path());
    Hash256 root2 = ingest_directory(store, dir2.path());

    // Verify reachable hashes never include symlink target hashes
    Hash256 link1_target_hash = Hasher::hash("new_dir/c.txt");
    Hash256 link2_target_hash = Hasher::hash("dir_to_file");
    auto reachable = collect_manifest_reachable_hashes(store, root2);
    TEST_CHECK_FALSE(reachable.count(link1_target_hash) > 0);
    TEST_CHECK_FALSE(reachable.count(link2_target_hash) > 0);
    for (const auto& h : reachable) {
        TEST_CHECK_TRUE(store.has_chunk(h));
    }

    ManifestDiff diff = diff_manifests(store, root1, root2);
    TEST_CHECK_FALSE(diff.needed_chunks.count(link1_target_hash) > 0);
    TEST_CHECK_FALSE(diff.needed_chunks.count(link2_target_hash) > 0);
    for (const auto& h : diff.needed_chunks) {
        TEST_CHECK_TRUE(store.has_chunk(h));
    }

    std::set<std::string> added(diff.added_files.begin(), diff.added_files.end());
    std::set<std::string> deleted(diff.deleted_files.begin(), diff.deleted_files.end());
    std::set<std::string> modified(diff.modified_files.begin(), diff.modified_files.end());

    TEST_CHECK_TRUE(added.count("new_dir/c.txt") > 0);
    TEST_CHECK_TRUE(added.count("new_dir/sub/d.txt") > 0);
    TEST_CHECK_TRUE(added.count("dir_to_file") > 0);
    TEST_CHECK_TRUE(added.count("file_to_dir/child.txt") > 0);
    TEST_CHECK_TRUE(added.count("link2") > 0);
    TEST_CHECK_FALSE(added.count("new_dir") > 0);
    TEST_CHECK_FALSE(added.count("new_dir/sub") > 0);

    TEST_CHECK_TRUE(deleted.count("old_dir/a.txt") > 0);
    TEST_CHECK_TRUE(deleted.count("old_dir/nested/b.txt") > 0);
    TEST_CHECK_TRUE(deleted.count("dir_to_file/inside.txt") > 0);
    TEST_CHECK_TRUE(deleted.count("file_to_dir") > 0);
    TEST_CHECK_FALSE(deleted.count("old_dir") > 0);
    TEST_CHECK_FALSE(deleted.count("old_dir/nested") > 0);

    TEST_CHECK_TRUE(modified.count("link1") > 0);
}

void test_checkout_validation_and_missing_chunks() {
    ScopedTempDir dst_dir("test_checkout_val_dst");
    ScopedTempDir store_dir("test_checkout_val_store");
    Store store(store_dir.path());

    // 1. Path traversal in manifest entry name must fail cleanly
    for (const char* bad_name : {"../escape.txt", "..", ".", "sub/escape.txt", "sub\\escape.txt", ""}) {
        Manifest bad_man;
        FileEntry fe;
        fe.name = bad_name;
        fe.kind = EntryKind::Regular;
        fe.size = 5;
        fe.hash = store.put_chunk("hello", 5);
        bad_man.add_entry(fe);
        Hash256 bad_root = store.put_chunk(bad_man.serialize());

        auto stats = checkout_directory(store, bad_root, dst_dir.path() / "sub");
        TEST_CHECK_FALSE(stats.has_value());
        TEST_CHECK_TRUE(stats == std::nullopt);
        TEST_CHECK_FALSE(std::filesystem::exists(dst_dir.path() / "escape.txt"));
    }

    // 2. Missing regular file chunk must fail checkout
    {
        Manifest man;
        FileEntry fe;
        fe.name = "missing.txt";
        fe.kind = EntryKind::Regular;
        fe.size = 12;
        fe.hash = Hasher::hash("missing data");
        man.add_entry(fe);
        Hash256 root = store.put_chunk(man.serialize());

        auto stats = checkout_directory(store, root, dst_dir.path() / "missing_reg");
        TEST_CHECK_FALSE(stats.has_value());
        TEST_CHECK_TRUE(stats == std::nullopt);
    }

    // 3. Missing chunk inside MultiChunkRegular must fail checkout and not leave partial file
    {
        FileManifest fm;
        fm.total_size = 10;
        ChunkInfo c1;
        c1.hash = store.put_chunk("12345", 5);
        c1.offset = 0;
        c1.size = 5;
        ChunkInfo c2;
        c2.hash = Hasher::hash("67890_missing");
        c2.offset = 5;
        c2.size = 5;
        fm.chunks.push_back(c1);
        fm.chunks.push_back(c2);
        Hash256 fm_hash = store.put_chunk(fm.serialize());

        Manifest man;
        FileEntry fe;
        fe.name = "multichunk.bin";
        fe.kind = EntryKind::MultiChunkRegular;
        fe.size = 10;
        fe.hash = fm_hash;
        man.add_entry(fe);
        Hash256 root = store.put_chunk(man.serialize());

        auto target = dst_dir.path() / "missing_mc";
        auto stats = checkout_directory(store, root, target);
        TEST_CHECK_FALSE(stats.has_value());
        TEST_CHECK_TRUE(stats == std::nullopt);
        TEST_CHECK_FALSE(std::filesystem::exists(target / "multichunk.bin"));
    }
}

int main() {
    test_manifest_round_trip();
    test_manifest_diff_and_deduplication();
    test_manifest_diff_recursive_dirs_and_symlinks();
    test_checkout_validation_and_missing_chunks();
    std::cout << "All manifest tests passed!" << std::endl;
    return 0;
}
