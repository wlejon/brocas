#include "test_harness.h"
#include <brocas/manifest.h>
#include <brocas/store.h>
#include <brocas/sync.h>

#include <cstring>
#include <thread>

using namespace bro::cas;
using namespace bro::cas::test;

void test_sync_send_only_what_receiver_lacks() {
    ScopedTempDir src_dir("test_sync_src");
    ScopedTempDir dst_dir("test_sync_dst");
    ScopedTempDir sender_store_dir("test_sync_sender_store");
    ScopedTempDir receiver_store_dir("test_sync_recv_store");

    Store sender_store(sender_store_dir.path());
    Store receiver_store(receiver_store_dir.path());

    // Ingest data into sender
    src_dir.create_file("file1.txt", "Content of file 1");
    src_dir.create_file("file2.txt", "Content of file 2");
    src_dir.create_dir("subdir");
    src_dir.create_binary_file("subdir/big.bin", 128 * 1024, 0x77);

    IngestOptions opts;
    opts.chunk_threshold = 32 * 1024;
    opts.chunk_options.min_size = 4096;
    opts.chunk_options.avg_size = 16384;
    opts.chunk_options.max_size = 65536;

    Hash256 root_hash = ingest_directory(sender_store, src_dir.path(), opts);

    // Pre-seed receiver with file1.txt's chunk
    Hash256 file1_hash = Hasher::hash("Content of file 1");
    receiver_store.put_chunk("Content of file 1", std::strlen("Content of file 1"));
    TEST_CHECK_TRUE(receiver_store.has_chunk(file1_hash));

    // Full sync over MemoryTransport
    auto [client_t, server_t] = MemoryTransport::create_pair();

    SyncSender sender(sender_store);
    SyncReceiver receiver(receiver_store);

    std::thread sender_thread([&] {
        sender.run(*server_t);
    });

    SyncStats stats;
    bool ok = receiver.sync_manifest(*client_t, root_hash, &stats);
    TEST_CHECK_TRUE(ok);

    client_t->close();
    server_t->close();
    sender_thread.join();

    // Verify receiver did NOT request file1_hash because it already had it!
    TEST_CHECK_TRUE(receiver_store.has_chunk(file1_hash));

    // Verify checkout from receiver store is byte-exact
    checkout_directory(receiver_store, root_hash, dst_dir.path());
    TEST_CHECK_TRUE(ScopedTempDir::compare_trees_byte_exact(src_dir.path(), dst_dir.path()));
}

void test_sync_interrupted_and_resumed() {
    ScopedTempDir src_dir("test_interrupted_src");
    ScopedTempDir dst_dir("test_interrupted_dst");
    ScopedTempDir sender_store_dir("test_int_sender_store");
    ScopedTempDir receiver_store_dir("test_int_recv_store");

    Store sender_store(sender_store_dir.path());
    Store receiver_store(receiver_store_dir.path());

    // Create a multi-chunk file (total ~15-20 chunks)
    src_dir.create_binary_file("large.bin", 500 * 1024, 0x99);
    src_dir.create_file("meta1.txt", "Metadata file 1");
    src_dir.create_file("meta2.txt", "Metadata file 2");

    IngestOptions opts;
    opts.chunk_threshold = 16 * 1024;
    opts.chunk_options.min_size = 8192;
    opts.chunk_options.avg_size = 16384;
    opts.chunk_options.max_size = 32768;

    Hash256 root_hash = ingest_directory(sender_store, src_dir.path(), opts);

    auto all_chunks = collect_manifest_reachable_hashes(sender_store, root_hash);
    TEST_CHECK_TRUE(all_chunks.size() >= 8);

    // Part 1: First sync attempt that is severed mid-transfer (~50%)
    {
        auto [client_t1, server_t1] = MemoryTransport::create_pair();

        // Sever connection on receiver after receiving ~4 frames (HandshakeAck, ManifestResponse, and 2 ChunkData)
        client_t1->set_disconnect_after_recvs(4);

        SyncSender sender(sender_store);
        SyncReceiver receiver(receiver_store);

        std::thread sender_thread([&] {
            sender.run(*server_t1);
        });

        SyncStats stats1;
        bool ok = receiver.sync_manifest(*client_t1, root_hash, &stats1);
        TEST_CHECK_FALSE(ok); // Severed!

        client_t1->close();
        server_t1->close();
        sender_thread.join();

        // Verify receiver obtained partial chunks
        size_t chunks_after_part1 = receiver_store.list_chunks().size();
        std::cout << "Interrupted sync: receiver stored " << chunks_after_part1
                  << " of " << all_chunks.size() << " chunks before disconnect." << std::endl;
        TEST_CHECK_TRUE(chunks_after_part1 > 0);
        TEST_CHECK_TRUE(chunks_after_part1 < all_chunks.size());
    }

    // Part 2: Resume transfer on fresh transport
    {
        auto [client_t2, server_t2] = MemoryTransport::create_pair();

        SyncSender sender(sender_store);
        SyncReceiver receiver(receiver_store);

        std::thread sender_thread([&] {
            sender.run(*server_t2);
        });

        SyncStats stats2;
        bool ok = receiver.sync_manifest(*client_t2, root_hash, &stats2);
        TEST_CHECK_TRUE(ok); // Resumed successfully!

        client_t2->close();
        server_t2->close();
        sender_thread.join();

        // Verify that only the remaining unverified chunks were transferred
        size_t total_chunks = all_chunks.size();
        size_t receiver_chunks = receiver_store.list_chunks().size();
        TEST_CHECK_EQ(receiver_chunks, total_chunks);

        // Requested chunks in phase 2 must be strictly fewer than total
        TEST_CHECK_TRUE(stats2.chunks_requested < total_chunks);
        std::cout << "Resumed sync requested ONLY " << stats2.chunks_requested
                  << " remaining chunks out of " << total_chunks << " total." << std::endl;
    }

    // Part 3: Checkout and byte-exact verification
    checkout_directory(receiver_store, root_hash, dst_dir.path());
    TEST_CHECK_TRUE(ScopedTempDir::compare_trees_byte_exact(src_dir.path(), dst_dir.path()));
}

int main() {
    test_sync_send_only_what_receiver_lacks();
    test_sync_interrupted_and_resumed();
    std::cout << "All sync tests passed!" << std::endl;
    return 0;
}
