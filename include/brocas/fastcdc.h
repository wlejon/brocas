#pragma once

#include <brocas/hash.h>

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <iosfwd>
#include <span>
#include <vector>

namespace bro::cas {

struct ChunkOptions {
    uint32_t min_size = 16 * 1024;    // 16 KiB
    uint32_t avg_size = 64 * 1024;    // 64 KiB
    uint32_t max_size = 256 * 1024;   // 256 KiB
    uint32_t normalization = 1;       // Normalized chunking level N (default: 1, matching FastCDC 2016)
};

struct ChunkInfo {
    Hash256 hash;
    uint64_t offset = 0;
    uint32_t size = 0;
    uint64_t gear_hash = 0;

    auto operator<=>(const ChunkInfo& other) const = default;
    bool operator==(const ChunkInfo& other) const = default;
};

// Stream chunker for processing data without loading everything into RAM at once.
class FastCDCChunker {
public:
    explicit FastCDCChunker(ChunkOptions options = ChunkOptions());

    // Process a block of data. Calls on_chunk for each completed chunk.
    void update(const void* data, size_t size,
                const std::function<void(const ChunkInfo&, std::span<const uint8_t>)>& on_chunk);

    // Finalize processing. Flushes any remaining bytes as the last chunk.
    void finalize(const std::function<void(const ChunkInfo&, std::span<const uint8_t>)>& on_chunk);

    void reset();

    const ChunkOptions& options() const noexcept { return options_; }

private:
    ChunkOptions options_;
    uint64_t mask_s_ = 0;
    uint64_t mask_l_ = 0;

    uint64_t fp_ = 0;
    uint64_t total_offset_ = 0;
    std::vector<uint8_t> pending_bytes_;
};

// Convenience chunking functions
std::vector<ChunkInfo> chunk_buffer(const void* data, size_t size,
                                   ChunkOptions options = ChunkOptions());

std::vector<ChunkInfo> chunk_buffer(std::span<const uint8_t> data,
                                   ChunkOptions options = ChunkOptions());

std::vector<ChunkInfo> chunk_file(const std::filesystem::path& path,
                                 ChunkOptions options = ChunkOptions());

void chunk_stream(std::istream& is,
                  const std::function<void(const ChunkInfo&, std::span<const uint8_t>)>& on_chunk,
                  ChunkOptions options = ChunkOptions());

} // namespace bro::cas
