#include "test_harness.h"
#include <brocas/manifest.h>
#include <brocas/store.h>

#include <fstream>

using namespace bro::cas;
using namespace bro::cas::test;

void test_store_basic() {
    ScopedTempDir temp("test_store_basic");
    Store store(temp.path());

    std::string payload = "The quick brown fox jumps over the lazy dog";
    Hash256 h = store.put_chunk(payload.data(), payload.size());

    TEST_CHECK_TRUE(store.has_chunk(h));
    auto sz = store.chunk_size(h);
    TEST_CHECK_TRUE(sz.has_value());
    TEST_CHECK_EQ(*sz, static_cast<uint64_t>(payload.size()));

    // Verify sharded path layout: .cas/chunks/ab/cd/<hash>
    auto p = store.chunk_path(h);
    std::string hex = h.to_hex();
    TEST_CHECK_EQ(p.parent_path().parent_path().filename().string(), hex.substr(0, 2));
    TEST_CHECK_EQ(p.parent_path().filename().string(), hex.substr(2, 2));
    TEST_CHECK_EQ(p.filename().string(), hex);

    // Read back
    auto read_data = store.read_chunk(h);
    TEST_CHECK_TRUE(read_data.has_value());
    TEST_CHECK_EQ(std::string(read_data->begin(), read_data->end()), payload);

    // Deduplication: writing again succeeds
    TEST_CHECK_TRUE(store.write_chunk(h, payload.data(), payload.size()));
}

void test_store_integrity_check() {
    ScopedTempDir temp("test_store_integrity");
    Store store(temp.path());

    std::string payload = "Data to be intentionally corrupted on disk";
    Hash256 h = store.put_chunk(payload.data(), payload.size());

    // Chunk is valid initially
    TEST_CHECK_TRUE(store.read_chunk(h).has_value());

    // Corrupt 1 byte in the chunk file on disk
    auto path = store.chunk_path(h);
    {
        std::fstream f(path, std::ios::in | std::ios::out | std::ios::binary);
        f.seekp(0);
        char b = 0;
        f.read(&b, 1);
        b ^= 0xFF;
        f.seekp(0);
        f.write(&b, 1);
    }

    // Now reading chunk must detect corruption and return nullopt
    auto corrupt_read = store.read_chunk(h);
    TEST_CHECK_FALSE(corrupt_read.has_value());
}

void test_store_roots_and_gc() {
    ScopedTempDir temp("test_store_roots");
    Store store(temp.path());

    // Create chunks
    std::string data1 = "Chunk 1 content";
    std::string data2 = "Chunk 2 content";
    std::string data3 = "Chunk 3 unreferenced content";
    std::string data4 = "Chunk 4 unreferenced content";

    Hash256 h1 = store.put_chunk(data1.data(), data1.size());
    Hash256 h2 = store.put_chunk(data2.data(), data2.size());
    Hash256 h3 = store.put_chunk(data3.data(), data3.size());
    Hash256 h4 = store.put_chunk(data4.data(), data4.size());

    // Create a manifest referencing h1 and h2
    Manifest manifest;
    FileEntry e1;
    e1.name = "file1.txt";
    e1.kind = EntryKind::Regular;
    e1.size = data1.size();
    e1.hash = h1;
    manifest.add_entry(e1);

    FileEntry e2;
    e2.name = "file2.txt";
    e2.kind = EntryKind::Regular;
    e2.size = data2.size();
    e2.hash = h2;
    manifest.add_entry(e2);

    manifest.sort();
    auto man_bytes = manifest.serialize();
    Hash256 man_hash = store.put_chunk(man_bytes);

    // Register root
    TEST_CHECK_TRUE(store.register_root("release-1.0", man_hash));
    auto root_opt = store.get_root("release-1.0");
    TEST_CHECK_TRUE(root_opt.has_value());
    TEST_CHECK_EQ(*root_opt, man_hash);

    auto roots = store.list_roots();
    TEST_CHECK_EQ(roots.size(), 1U);
    TEST_CHECK_EQ(roots[0].first, "release-1.0");
    TEST_CHECK_EQ(roots[0].second, man_hash);

    // Run GC: h3 and h4 should be swept, h1, h2, man_hash kept
    GCStats stats1 = store.collect_garbage();
    TEST_CHECK_EQ(stats1.chunks_reclaimed, 2U);
    TEST_CHECK_EQ(stats1.chunks_kept, 3U); // man_hash, h1, h2
    TEST_CHECK_EQ(stats1.bytes_reclaimed, data3.size() + data4.size());

    TEST_CHECK_TRUE(store.has_chunk(h1));
    TEST_CHECK_TRUE(store.has_chunk(h2));
    TEST_CHECK_TRUE(store.has_chunk(man_hash));
    TEST_CHECK_FALSE(store.has_chunk(h3));
    TEST_CHECK_FALSE(store.has_chunk(h4));

    // Unregister root
    TEST_CHECK_TRUE(store.unregister_root("release-1.0"));
    TEST_CHECK_FALSE(store.get_root("release-1.0").has_value());

    // Run GC again: now everything should be swept
    GCStats stats2 = store.collect_garbage();
    TEST_CHECK_EQ(stats2.chunks_reclaimed, 3U);
    TEST_CHECK_EQ(stats2.chunks_kept, 0U);
    TEST_CHECK_FALSE(store.has_chunk(h1));
    TEST_CHECK_FALSE(store.has_chunk(h2));
    TEST_CHECK_FALSE(store.has_chunk(man_hash));
}

int main() {
    test_store_basic();
    test_store_integrity_check();
    test_store_roots_and_gc();
    std::cout << "All store tests passed!" << std::endl;
    return 0;
}
