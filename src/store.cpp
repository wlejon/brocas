#include <brocas/store.h>
#include <brocas/manifest.h>

#include <atomic>
#include <chrono>
#include <fstream>
#include <iostream>
#include <queue>
#include <system_error>
#include <unordered_set>

namespace bro::cas {

namespace {

std::atomic<uint64_t> g_temp_counter{0};

} // namespace

Store::Store(std::filesystem::path root_dir, StoreOptions options)
    : root_dir_(std::move(root_dir)),
      chunks_dir_(root_dir_ / "chunks"),
      tmp_dir_(root_dir_ / "tmp"),
      roots_dir_(root_dir_ / "roots"),
      options_(options) {
    init_directories();
}

void Store::init_directories() {
    std::error_code ec;
    std::filesystem::create_directories(chunks_dir_, ec);
    std::filesystem::create_directories(tmp_dir_, ec);
    std::filesystem::create_directories(roots_dir_, ec);
}

std::filesystem::path Store::chunk_path(const Hash256& hash) const {
    std::string hex = hash.to_hex();
    return chunks_dir_ / hex.substr(0, 2) / hex.substr(2, 2) / hex;
}

std::filesystem::path Store::make_temp_path() const {
    auto now = std::chrono::steady_clock::now().time_since_epoch().count();
    uint64_t count = g_temp_counter.fetch_add(1, std::memory_order_relaxed);
    std::string fname = "tmp_" + std::to_string(now) + "_" + std::to_string(count);
    return tmp_dir_ / fname;
}

bool Store::has_chunk(const Hash256& hash) const {
    std::error_code ec;
    return std::filesystem::exists(chunk_path(hash), ec);
}

std::optional<uint64_t> Store::chunk_size(const Hash256& hash) const {
    std::error_code ec;
    auto path = chunk_path(hash);
    if (!std::filesystem::exists(path, ec)) {
        return std::nullopt;
    }
    uint64_t size = std::filesystem::file_size(path, ec);
    if (ec) {
        return std::nullopt;
    }
    return size;
}

std::vector<Hash256> Store::list_chunks() const {
    std::vector<Hash256> out;
    std::error_code ec;
    if (!std::filesystem::exists(chunks_dir_, ec)) {
        return out;
    }

    for (const auto& entry : std::filesystem::recursive_directory_iterator(chunks_dir_, ec)) {
        if (ec) break;
        if (entry.is_regular_file(ec)) {
            std::string filename = entry.path().filename().string();
            if (auto h = Hash256::from_hex(filename)) {
                out.push_back(*h);
            }
        }
    }
    return out;
}

Hash256 Store::put_chunk(std::span<const uint8_t> data) {
    Hash256 hash = Hasher::hash(data);
    write_chunk(hash, data);
    return hash;
}

Hash256 Store::put_chunk(const void* data, size_t size) {
    if (data == nullptr || size == 0) {
        return put_chunk(std::span<const uint8_t>());
    }
    return put_chunk(std::span<const uint8_t>(static_cast<const uint8_t*>(data), size));
}

bool Store::write_chunk(const Hash256& hash, const void* data, size_t size) {
    if (data == nullptr || size == 0) {
        return write_chunk(hash, std::span<const uint8_t>());
    }
    return write_chunk(hash, std::span<const uint8_t>(static_cast<const uint8_t*>(data), size));
}

bool Store::write_chunk(const Hash256& hash, std::span<const uint8_t> data) {
    auto dest = chunk_path(hash);
    std::error_code ec;
    if (std::filesystem::exists(dest, ec)) {
        // Chunk deduplication: write once
        return true;
    }

    auto temp = make_temp_path();
    {
        std::ofstream file(temp, std::ios::binary | std::ios::trunc);
        if (!file.is_open()) {
            return false;
        }
        if (!data.empty()) {
            file.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));
        }
        file.flush();
        if (!file.good()) {
            file.close();
            std::filesystem::remove(temp, ec);
            return false;
        }
    }

    std::filesystem::create_directories(dest.parent_path(), ec);
    std::filesystem::rename(temp, dest, ec);
    if (ec) {
        // In case of race where another thread wrote the destination
        if (std::filesystem::exists(dest, ec)) {
            std::filesystem::remove(temp, ec);
            return true;
        }
        std::filesystem::remove(temp, ec);
        return false;
    }
    return true;
}

std::optional<std::vector<uint8_t>> Store::read_chunk(const Hash256& hash) const {
    std::vector<uint8_t> out;
    if (read_chunk_to(hash, out)) {
        return out;
    }
    return std::nullopt;
}

bool Store::read_chunk_to(const Hash256& hash, std::vector<uint8_t>& out) const {
    auto path = chunk_path(hash);
    std::error_code ec;
    if (!std::filesystem::exists(path, ec)) {
        return false;
    }

    uint64_t size = std::filesystem::file_size(path, ec);
    if (ec) return false;

    std::ifstream file(path, std::ios::binary);
    if (!file.is_open()) return false;

    out.resize(static_cast<size_t>(size));
    if (size > 0) {
        file.read(reinterpret_cast<char*>(out.data()), static_cast<std::streamsize>(size));
        if (!file.good() && !file.eof()) {
            out.clear();
            return false;
        }
    }

    if (options_.verify_on_read) {
        Hash256 computed = Hasher::hash(out.data(), out.size());
        if (computed != hash) {
            // Integrity failure
            out.clear();
            return false;
        }
    }
    return true;
}

bool Store::register_root(const std::string& name, const Hash256& root_hash) {
    if (name.empty()) return false;
    init_directories();

    auto path = roots_dir_ / name;
    std::error_code ec;
    std::filesystem::create_directories(path.parent_path(), ec);

    std::ofstream file(path, std::ios::trunc);
    if (!file.is_open()) return false;

    file << root_hash.to_hex() << "\n";
    return file.good();
}

bool Store::unregister_root(const std::string& name) {
    auto path = roots_dir_ / name;
    std::error_code ec;
    return std::filesystem::remove(path, ec);
}

std::optional<Hash256> Store::get_root(const std::string& name) const {
    auto path = roots_dir_ / name;
    std::ifstream file(path);
    if (!file.is_open()) return std::nullopt;

    std::string hex;
    file >> hex;
    return Hash256::from_hex(hex);
}

std::vector<std::pair<std::string, Hash256>> Store::list_roots() const {
    std::vector<std::pair<std::string, Hash256>> out;
    std::error_code ec;
    if (!std::filesystem::exists(roots_dir_, ec)) return out;

    for (const auto& entry : std::filesystem::directory_iterator(roots_dir_, ec)) {
        if (ec) break;
        if (entry.is_regular_file(ec)) {
            std::string name = entry.path().filename().string();
            if (auto h = get_root(name)) {
                out.emplace_back(std::move(name), *h);
            }
        }
    }
    return out;
}

std::vector<Hash256> find_manifest_references(const Hash256& object_hash, const Store& store) {
    std::vector<Hash256> refs;
    auto data = store.read_chunk(object_hash);
    if (!data) return refs;

    // Try Directory Manifest
    if (auto manifest = Manifest::deserialize(*data)) {
        for (const auto& entry : manifest->entries) {
            if (entry.kind == EntryKind::Directory ||
                entry.kind == EntryKind::Regular ||
                entry.kind == EntryKind::MultiChunkRegular) {
                if (!entry.hash.is_zero()) {
                    refs.push_back(entry.hash);
                }
            }
        }
        return refs;
    }

    // Try FileManifest
    if (auto file_manifest = FileManifest::deserialize(*data)) {
        for (const auto& chunk : file_manifest->chunks) {
            if (!chunk.hash.is_zero()) {
                refs.push_back(chunk.hash);
            }
        }
        return refs;
    }

    return refs;
}

GCStats Store::collect_garbage(ReferenceFinder finder) {
    if (!finder) {
        finder = find_manifest_references;
    }

    std::unordered_set<Hash256> reachable;
    std::queue<Hash256> queue;

    auto roots = list_roots();
    for (const auto& [name, root_hash] : roots) {
        if (!root_hash.is_zero() && reachable.insert(root_hash).second) {
            queue.push(root_hash);
        }
    }

    while (!queue.empty()) {
        Hash256 curr = queue.front();
        queue.pop();

        auto refs = finder(curr, *this);
        for (const auto& ref : refs) {
            if (!ref.is_zero() && reachable.insert(ref).second) {
                queue.push(ref);
            }
        }
    }

    GCStats stats;
    std::error_code ec;
    if (!std::filesystem::exists(chunks_dir_, ec)) {
        return stats;
    }

    std::vector<std::filesystem::path> to_remove;
    for (const auto& entry : std::filesystem::recursive_directory_iterator(chunks_dir_, ec)) {
        if (ec) break;
        if (entry.is_regular_file(ec)) {
            std::string filename = entry.path().filename().string();
            auto h = Hash256::from_hex(filename);
            uint64_t size = entry.file_size(ec);

            if (h && reachable.find(*h) != reachable.end()) {
                stats.chunks_kept++;
                stats.bytes_kept += size;
            } else {
                to_remove.push_back(entry.path());
                stats.chunks_reclaimed++;
                stats.bytes_reclaimed += size;
            }
        }
    }

    for (const auto& path : to_remove) {
        std::filesystem::remove(path, ec);
    }

    // Clean up empty directories safely bottom-up
    for (const auto& d1 : std::filesystem::directory_iterator(chunks_dir_, ec)) {
        if (ec) break;
        if (d1.is_directory(ec)) {
            for (const auto& d2 : std::filesystem::directory_iterator(d1.path(), ec)) {
                if (ec) break;
                if (d2.is_directory(ec)) {
                    std::filesystem::remove(d2.path(), ec);
                }
            }
            std::filesystem::remove(d1.path(), ec);
        }
    }

    return stats;
}

} // namespace bro::cas
