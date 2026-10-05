#include "test_harness.h"
#include <brocas/manifest.h>
#include <brocas/protocol.h>

#include <random>
#include <vector>

using namespace bro::cas;

void test_fuzz_manifest() {
    // 1. Create a sample valid manifest
    Manifest man;
    FileEntry e1;
    e1.name = "fuzz_test_1.txt";
    e1.kind = EntryKind::Regular;
    e1.size = 1234;
    e1.mode = 0644;
    e1.mtime = 1700000000;
    e1.hash = Hasher::hash("sample content 1");
    man.add_entry(e1);

    FileEntry e2;
    e2.name = "sub";
    e2.kind = EntryKind::Directory;
    e2.hash = Hasher::hash("sample dir");
    man.add_entry(e2);

    auto valid_bytes = man.serialize();

    // Test all prefix truncations
    for (size_t len = 0; len < valid_bytes.size(); ++len) {
        auto result = Manifest::deserialize(std::span<const uint8_t>(valid_bytes.data(), len));
        (void)result;
    }

    // Test bit flips on valid bytes
    std::mt19937 rng(42);
    for (int iter = 0; iter < 1000; ++iter) {
        auto mutated = valid_bytes;
        size_t flips = (rng() % 5) + 1;
        for (size_t f = 0; f < flips; ++f) {
            size_t idx = rng() % mutated.size();
            mutated[idx] ^= static_cast<uint8_t>(rng() & 0xFF);
        }
        auto result = Manifest::deserialize(mutated);
        (void)result;
    }

    // Test arbitrary random buffers
    for (int iter = 0; iter < 500; ++iter) {
        size_t len = rng() % 2048;
        std::vector<uint8_t> rand_buf(len);
        for (size_t i = 0; i < len; ++i) {
            rand_buf[i] = static_cast<uint8_t>(rng() & 0xFF);
        }
        auto result = Manifest::deserialize(rand_buf);
        (void)result;
    }
}

void test_fuzz_file_manifest() {
    FileManifest fm;
    fm.total_size = 999999;
    for (int i = 0; i < 10; ++i) {
        ChunkInfo c;
        c.hash = Hasher::hash(std::to_string(i));
        c.offset = i * 1000;
        c.size = 1000;
        fm.chunks.push_back(c);
    }

    auto valid_bytes = fm.serialize();

    // All prefix truncations
    for (size_t len = 0; len < valid_bytes.size(); ++len) {
        auto result = FileManifest::deserialize(std::span<const uint8_t>(valid_bytes.data(), len));
        (void)result;
    }

    // Random byte streams
    std::mt19937 rng(1337);
    for (int iter = 0; iter < 500; ++iter) {
        size_t len = rng() % 2048;
        std::vector<uint8_t> rand_buf(len);
        for (size_t i = 0; i < len; ++i) {
            rand_buf[i] = static_cast<uint8_t>(rng() & 0xFF);
        }
        auto result = FileManifest::deserialize(rand_buf);
        (void)result;
    }
}

void test_fuzz_wire_framing() {
    WireFraming framing;

    // Create a valid frame
    std::string payload = "Fuzz test payload for wire protocol framing";
    auto valid_frame_bytes = WireFraming::encode(MessageType::ChunkData,
        std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(payload.data()), payload.size()));

    // Truncations fed 1 byte at a time
    for (size_t i = 0; i < valid_frame_bytes.size(); ++i) {
        framing.feed(&valid_frame_bytes[i], 1);
        auto f = framing.pop_frame();
        if (i + 1 < valid_frame_bytes.size()) {
            TEST_CHECK_FALSE(f.has_value());
        } else {
            TEST_CHECK_TRUE(f.has_value());
            TEST_CHECK_EQ(f->type, MessageType::ChunkData);
        }
    }

    // Mutated CRC
    {
        auto mutated = valid_frame_bytes;
        mutated.back() ^= 0xFF; // Invalidate CRC
        framing.feed(mutated);
        auto f = framing.pop_frame();
        TEST_CHECK_FALSE(f.has_value());
    }

    // Random byte streams into framing parser
    std::mt19937 rng(0xBEEF);
    for (int iter = 0; iter < 200; ++iter) {
        size_t chunk_len = (rng() % 512) + 1;
        std::vector<uint8_t> rand_bytes(chunk_len);
        for (size_t i = 0; i < chunk_len; ++i) {
            rand_bytes[i] = static_cast<uint8_t>(rng() & 0xFF);
        }
        framing.feed(rand_bytes);
        // Pop any frames that happen to match or skip invalid
        while (framing.pop_frame().has_value()) {}
    }
    framing.reset();
}

void test_fuzz_messages() {
    std::mt19937 rng(999);
    for (int iter = 0; iter < 200; ++iter) {
        size_t len = rng() % 256;
        std::vector<uint8_t> bytes(len);
        for (size_t i = 0; i < len; ++i) {
            bytes[i] = static_cast<uint8_t>(rng() & 0xFF);
        }

        (void)HandshakeMsg::deserialize(bytes);
        (void)HandshakeAckMsg::deserialize(bytes);
        (void)ManifestRequestMsg::deserialize(bytes);
        (void)ManifestResponseMsg::deserialize(bytes);
        (void)HaveQueryMsg::deserialize(bytes);
        (void)HaveResponseMsg::deserialize(bytes);
        (void)WantChunksMsg::deserialize(bytes);
        (void)ChunkDataMsg::deserialize(bytes);
        (void)CompleteMsg::deserialize(bytes);
        (void)ErrorMsg::deserialize(bytes);
    }
}

int main() {
    test_fuzz_manifest();
    test_fuzz_file_manifest();
    test_fuzz_wire_framing();
    test_fuzz_messages();
    std::cout << "All fuzz tests passed cleanly without crashes!" << std::endl;
    return 0;
}
