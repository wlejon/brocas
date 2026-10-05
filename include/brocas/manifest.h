#pragma once

#include <brocas/fastcdc.h>
#include <brocas/hash.h>
#include <brocas/store.h>

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <ostream>
#include <set>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace bro::cas {

enum class EntryKind : uint8_t {
    Regular = 1,
    Directory = 2,
    Symlink = 3,
    MultiChunkRegular = 4
};

const char* to_string(EntryKind kind) noexcept;

inline std::ostream& operator<<(std::ostream& os, EntryKind kind) {
    return os << to_string(kind);
}

struct FileEntry {
    std::string name;
    EntryKind kind = EntryKind::Regular;
    uint64_t size = 0;
    uint32_t mode = 0644;
    uint64_t mtime = 0;
    std::string symlink_target;
    Hash256 hash;

    auto operator<=>(const FileEntry& other) const = default;
    bool operator==(const FileEntry& other) const = default;
};

struct Manifest {
    std::vector<FileEntry> entries;

    void add_entry(FileEntry entry);
    const FileEntry* find_entry(std::string_view name) const;
    void sort();

    std::vector<uint8_t> serialize() const;
    static std::optional<Manifest> deserialize(std::span<const uint8_t> bytes);
};

struct FileManifest {
    uint64_t total_size = 0;
    std::vector<ChunkInfo> chunks;

    std::vector<uint8_t> serialize() const;
    static std::optional<FileManifest> deserialize(std::span<const uint8_t> bytes);
};

struct IngestOptions {
    uint32_t chunk_threshold = 64 * 1024;
    ChunkOptions chunk_options = ChunkOptions();
};

struct CheckoutOptions {
    bool restore_permissions = true;
    bool restore_mtime = true;
    bool restore_symlinks = true;
};

struct CheckoutStats {
    size_t files_created = 0;
    size_t dirs_created = 0;
    size_t symlinks_created = 0;
    uint64_t total_bytes = 0;

    auto operator<=>(const CheckoutStats& other) const = default;
    bool operator==(const CheckoutStats& other) const = default;
};

struct ManifestDiff {
    std::vector<std::string> added_files;
    std::vector<std::string> modified_files;
    std::vector<std::string> deleted_files;
    std::set<Hash256> needed_chunks;

    bool is_empty() const noexcept {
        return added_files.empty() && modified_files.empty() &&
               deleted_files.empty() && needed_chunks.empty();
    }
};

Hash256 ingest_directory(Store& store, const std::filesystem::path& dir,
                         IngestOptions options = IngestOptions());

CheckoutStats checkout_directory(const Store& store, const Hash256& root_hash,
                                 const std::filesystem::path& target_dir,
                                 CheckoutOptions options = CheckoutOptions());

ManifestDiff diff_manifests(const Store& store, const Hash256& old_root, const Hash256& new_root);

// Collects all chunk and manifest hashes reachable from a root manifest
std::set<Hash256> collect_manifest_reachable_hashes(const Store& store, const Hash256& root_hash);

} // namespace bro::cas
