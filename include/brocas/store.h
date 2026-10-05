#pragma once

#include <brocas/hash.h>

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <optional>
#include <span>
#include <string>
#include <utility>
#include <vector>

namespace bro::cas {

struct GCStats {
    uint64_t bytes_reclaimed = 0;
    size_t chunks_reclaimed = 0;
    uint64_t bytes_kept = 0;
    size_t chunks_kept = 0;

    auto operator<=>(const GCStats& other) const = default;
    bool operator==(const GCStats& other) const = default;
};

struct StoreOptions {
    bool verify_on_read = true;
};

class Store {
public:
    explicit Store(std::filesystem::path root_dir, StoreOptions options = StoreOptions());
    ~Store() = default;

    const std::filesystem::path& root_dir() const noexcept { return root_dir_; }
    const StoreOptions& options() const noexcept { return options_; }

    // Path helper for chunks
    std::filesystem::path chunk_path(const Hash256& hash) const;

    // Chunk queries
    bool has_chunk(const Hash256& hash) const;
    std::optional<uint64_t> chunk_size(const Hash256& hash) const;
    std::vector<Hash256> list_chunks() const;

    // Chunk writing
    Hash256 put_chunk(std::span<const uint8_t> data);
    Hash256 put_chunk(const void* data, size_t size);
    bool write_chunk(const Hash256& hash, std::span<const uint8_t> data);
    bool write_chunk(const Hash256& hash, const void* data, size_t size);

    // Chunk reading
    std::optional<std::vector<uint8_t>> read_chunk(const Hash256& hash) const;
    bool read_chunk_to(const Hash256& hash, std::vector<uint8_t>& out) const;

    // Root management
    bool register_root(const std::string& name, const Hash256& root_hash);
    bool unregister_root(const std::string& name);
    std::optional<Hash256> get_root(const std::string& name) const;
    std::vector<std::pair<std::string, Hash256>> list_roots() const;

    // Reachability callback for GC: returns all chunk hashes directly referenced by this object.
    using ReferenceFinder = std::function<std::vector<Hash256>(const Hash256& object_hash, const Store& store)>;

    // Garbage Collection: sweeps unreferenced chunks starting from all registered roots.
    // If finder is provided, uses it to discover referenced chunks; otherwise uses default manifest parser.
    GCStats collect_garbage(ReferenceFinder finder = ReferenceFinder());

private:
    std::filesystem::path root_dir_;
    std::filesystem::path chunks_dir_;
    std::filesystem::path tmp_dir_;
    std::filesystem::path roots_dir_;
    StoreOptions options_;

    void init_directories();
    std::filesystem::path make_temp_path() const;
};

// Default reference finder for manifests and chunk manifests
std::vector<Hash256> find_manifest_references(const Hash256& root_hash, const Store& store);

} // namespace bro::cas
