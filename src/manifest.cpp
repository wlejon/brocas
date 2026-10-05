#include <brocas/manifest.h>

#include <algorithm>
#include <cstring>

namespace bro::cas {

namespace {

constexpr uint32_t kManifestMagic = 0x4D414E49; // "MANI"
constexpr uint32_t kFileManifestMagic = 0x46494C45; // "FILE"
constexpr uint16_t kFormatVersion = 1;

void write_u16(std::vector<uint8_t>& buf, uint16_t val) {
    buf.push_back(static_cast<uint8_t>(val & 0xFF));
    buf.push_back(static_cast<uint8_t>((val >> 8) & 0xFF));
}

void write_u32(std::vector<uint8_t>& buf, uint32_t val) {
    for (int i = 0; i < 4; ++i) {
        buf.push_back(static_cast<uint8_t>((val >> (i * 8)) & 0xFF));
    }
}

void write_u64(std::vector<uint8_t>& buf, uint64_t val) {
    for (int i = 0; i < 8; ++i) {
        buf.push_back(static_cast<uint8_t>((val >> (i * 8)) & 0xFF));
    }
}

bool read_u16(std::span<const uint8_t>& src, uint16_t& out) {
    if (src.size() < 2) return false;
    out = static_cast<uint16_t>(src[0]) | (static_cast<uint16_t>(src[1]) << 8);
    src = src.subspan(2);
    return true;
}

bool read_u32(std::span<const uint8_t>& src, uint32_t& out) {
    if (src.size() < 4) return false;
    out = 0;
    for (size_t i = 0; i < 4; ++i) {
        out |= (static_cast<uint32_t>(src[i]) << (i * 8));
    }
    src = src.subspan(4);
    return true;
}

bool read_u64(std::span<const uint8_t>& src, uint64_t& out) {
    if (src.size() < 8) return false;
    out = 0;
    for (size_t i = 0; i < 8; ++i) {
        out |= (static_cast<uint64_t>(src[i]) << (i * 8));
    }
    src = src.subspan(8);
    return true;
}

} // namespace

const char* to_string(EntryKind kind) noexcept {
    switch (kind) {
        case EntryKind::Regular: return "Regular";
        case EntryKind::Directory: return "Directory";
        case EntryKind::Symlink: return "Symlink";
        case EntryKind::MultiChunkRegular: return "MultiChunkRegular";
        default: return "Unknown";
    }
}

void Manifest::add_entry(FileEntry entry) {
    entries.push_back(std::move(entry));
}

const FileEntry* Manifest::find_entry(std::string_view name) const {
    for (const auto& entry : entries) {
        if (entry.name == name) {
            return &entry;
        }
    }
    return nullptr;
}

void Manifest::sort() {
    std::sort(entries.begin(), entries.end(), [](const FileEntry& a, const FileEntry& b) {
        return a.name < b.name;
    });
}

std::vector<uint8_t> Manifest::serialize() const {
    std::vector<uint8_t> buf;
    buf.reserve(64 + entries.size() * 80);

    write_u32(buf, kManifestMagic);
    write_u16(buf, kFormatVersion);
    write_u16(buf, 0); // reserved
    write_u32(buf, static_cast<uint32_t>(entries.size()));

    for (const auto& entry : entries) {
        uint16_t name_len = static_cast<uint16_t>(std::min(entry.name.size(), static_cast<size_t>(0xFFFF)));
        write_u16(buf, name_len);
        buf.insert(buf.end(), entry.name.data(), entry.name.data() + name_len);

        buf.push_back(static_cast<uint8_t>(entry.kind));
        write_u64(buf, entry.size);
        write_u32(buf, entry.mode);
        write_u64(buf, entry.mtime);

        uint16_t sym_len = static_cast<uint16_t>(std::min(entry.symlink_target.size(), static_cast<size_t>(0xFFFF)));
        write_u16(buf, sym_len);
        buf.insert(buf.end(), entry.symlink_target.data(), entry.symlink_target.data() + sym_len);

        buf.insert(buf.end(), entry.hash.data(), entry.hash.data() + Hash256::kSize);
    }

    return buf;
}

std::optional<Manifest> Manifest::deserialize(std::span<const uint8_t> bytes) {
    if (bytes.size() < 12) {
        return std::nullopt;
    }

    uint32_t magic = 0;
    uint16_t version = 0;
    uint16_t reserved = 0;
    uint32_t entry_count = 0;

    std::span<const uint8_t> cursor = bytes;
    if (!read_u32(cursor, magic) || magic != kManifestMagic) return std::nullopt;
    if (!read_u16(cursor, version) || version != kFormatVersion) return std::nullopt;
    if (!read_u16(cursor, reserved)) return std::nullopt;
    if (!read_u32(cursor, entry_count)) return std::nullopt;

    // Minimum size of an entry: 2 (name_len) + 1 (kind) + 8 (size) + 4 (mode) + 8 (mtime) + 2 (sym_len) + 32 (hash) = 57 bytes
    if (static_cast<uint64_t>(entry_count) * 57 > cursor.size()) {
        return std::nullopt;
    }

    Manifest manifest;
    manifest.entries.reserve(entry_count);

    for (uint32_t i = 0; i < entry_count; ++i) {
        uint16_t name_len = 0;
        if (!read_u16(cursor, name_len) || cursor.size() < name_len) return std::nullopt;
        std::string name(reinterpret_cast<const char*>(cursor.data()), name_len);
        cursor = cursor.subspan(name_len);

        if (cursor.empty()) return std::nullopt;
        uint8_t raw_kind = cursor[0];
        cursor = cursor.subspan(1);
        if (raw_kind < 1 || raw_kind > 4) return std::nullopt;
        EntryKind kind = static_cast<EntryKind>(raw_kind);

        uint64_t size = 0;
        uint32_t mode = 0;
        uint64_t mtime = 0;
        if (!read_u64(cursor, size)) return std::nullopt;
        if (!read_u32(cursor, mode)) return std::nullopt;
        if (!read_u64(cursor, mtime)) return std::nullopt;

        uint16_t sym_len = 0;
        if (!read_u16(cursor, sym_len) || cursor.size() < sym_len) return std::nullopt;
        std::string sym_target(reinterpret_cast<const char*>(cursor.data()), sym_len);
        cursor = cursor.subspan(sym_len);

        if (cursor.size() < Hash256::kSize) return std::nullopt;
        Hash256 hash(cursor.data());
        cursor = cursor.subspan(Hash256::kSize);

        FileEntry entry;
        entry.name = std::move(name);
        entry.kind = kind;
        entry.size = size;
        entry.mode = mode;
        entry.mtime = mtime;
        entry.symlink_target = std::move(sym_target);
        entry.hash = hash;

        manifest.entries.push_back(std::move(entry));
    }

    return manifest;
}

std::vector<uint8_t> FileManifest::serialize() const {
    std::vector<uint8_t> buf;
    buf.reserve(20 + chunks.size() * (Hash256::kSize + 8 + 4));

    write_u32(buf, kFileManifestMagic);
    write_u16(buf, kFormatVersion);
    write_u16(buf, 0); // reserved
    write_u64(buf, total_size);
    write_u32(buf, static_cast<uint32_t>(chunks.size()));

    for (const auto& chunk : chunks) {
        buf.insert(buf.end(), chunk.hash.data(), chunk.hash.data() + Hash256::kSize);
        write_u64(buf, chunk.offset);
        write_u32(buf, chunk.size);
    }

    return buf;
}

std::optional<FileManifest> FileManifest::deserialize(std::span<const uint8_t> bytes) {
    if (bytes.size() < 20) {
        return std::nullopt;
    }

    uint32_t magic = 0;
    uint16_t version = 0;
    uint16_t reserved = 0;
    uint64_t total_size = 0;
    uint32_t chunk_count = 0;

    std::span<const uint8_t> cursor = bytes;
    if (!read_u32(cursor, magic) || magic != kFileManifestMagic) return std::nullopt;
    if (!read_u16(cursor, version) || version != kFormatVersion) return std::nullopt;
    if (!read_u16(cursor, reserved)) return std::nullopt;
    if (!read_u64(cursor, total_size)) return std::nullopt;
    if (!read_u32(cursor, chunk_count)) return std::nullopt;

    // Each chunk requires: 32 (hash) + 8 (offset) + 4 (size) = 44 bytes
    if (static_cast<uint64_t>(chunk_count) * 44 > cursor.size()) {
        return std::nullopt;
    }

    FileManifest manifest;
    manifest.total_size = total_size;
    manifest.chunks.reserve(chunk_count);

    for (uint32_t i = 0; i < chunk_count; ++i) {
        if (cursor.size() < Hash256::kSize) return std::nullopt;
        Hash256 hash(cursor.data());
        cursor = cursor.subspan(Hash256::kSize);

        uint64_t offset = 0;
        uint32_t size = 0;
        if (!read_u64(cursor, offset)) return std::nullopt;
        if (!read_u32(cursor, size)) return std::nullopt;

        ChunkInfo chunk;
        chunk.hash = hash;
        chunk.offset = offset;
        chunk.size = size;

        manifest.chunks.push_back(chunk);
    }

    return manifest;
}

} // namespace bro::cas
