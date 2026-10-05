#include <brocas/manifest.h>

#include <map>
#include <queue>
#include <unordered_set>

namespace bro::cas {

namespace {

void collect_entry_hashes(const Store& store, const FileEntry& entry, std::set<Hash256>& out) {
    if (entry.hash.is_zero()) return;
    out.insert(entry.hash);

    if (entry.kind == EntryKind::Directory) {
        auto sub_hashes = collect_manifest_reachable_hashes(store, entry.hash);
        out.insert(sub_hashes.begin(), sub_hashes.end());
    } else if (entry.kind == EntryKind::MultiChunkRegular) {
        auto data = store.read_chunk(entry.hash);
        if (data) {
            if (auto fm = FileManifest::deserialize(*data)) {
                for (const auto& ch : fm->chunks) {
                    if (!ch.hash.is_zero()) {
                        out.insert(ch.hash);
                    }
                }
            }
        }
    }
}

void diff_recursive(const Store& store, const Hash256& old_hash, const Hash256& new_hash,
                    const std::string& prefix, ManifestDiff& diff) {
    if (old_hash == new_hash) return;

    std::optional<Manifest> old_man;
    if (!old_hash.is_zero()) {
        if (auto data = store.read_chunk(old_hash)) {
            old_man = Manifest::deserialize(*data);
        }
    }

    std::optional<Manifest> new_man;
    if (!new_hash.is_zero()) {
        if (auto data = store.read_chunk(new_hash)) {
            new_man = Manifest::deserialize(*data);
            diff.needed_chunks.insert(new_hash);
        }
    }

    std::map<std::string, const FileEntry*> old_entries;
    if (old_man) {
        for (const auto& e : old_man->entries) {
            old_entries[e.name] = &e;
        }
    }

    std::map<std::string, const FileEntry*> new_entries;
    if (new_man) {
        for (const auto& e : new_man->entries) {
            new_entries[e.name] = &e;
        }
    }

    // Process new and modified
    for (const auto& [name, new_entry] : new_entries) {
        std::string rel_path = prefix.empty() ? name : (prefix + "/" + name);
        auto it = old_entries.find(name);
        if (it == old_entries.end()) {
            diff.added_files.push_back(rel_path);
            collect_entry_hashes(store, *new_entry, diff.needed_chunks);
        } else {
            const auto* old_entry = it->second;
            if (old_entry->hash != new_entry->hash) {
                if (old_entry->kind == EntryKind::Directory && new_entry->kind == EntryKind::Directory) {
                    diff_recursive(store, old_entry->hash, new_entry->hash, rel_path, diff);
                } else {
                    diff.modified_files.push_back(rel_path);
                    collect_entry_hashes(store, *new_entry, diff.needed_chunks);
                }
            }
        }
    }

    // Process deleted
    for (const auto& [name, old_entry] : old_entries) {
        if (new_entries.find(name) == new_entries.end()) {
            std::string rel_path = prefix.empty() ? name : (prefix + "/" + name);
            diff.deleted_files.push_back(rel_path);
        }
    }
}

} // namespace

std::set<Hash256> collect_manifest_reachable_hashes(const Store& store, const Hash256& root_hash) {
    std::set<Hash256> reachable;
    if (root_hash.is_zero()) return reachable;

    std::queue<Hash256> queue;
    queue.push(root_hash);
    reachable.insert(root_hash);

    while (!queue.empty()) {
        Hash256 curr = queue.front();
        queue.pop();

        auto data = store.read_chunk(curr);
        if (!data) continue;

        if (auto man = Manifest::deserialize(*data)) {
            for (const auto& entry : man->entries) {
                if (!entry.hash.is_zero()) {
                    if (reachable.insert(entry.hash).second) {
                        if (entry.kind == EntryKind::Directory ||
                            entry.kind == EntryKind::MultiChunkRegular) {
                            queue.push(entry.hash);
                        }
                    }
                }
            }
        } else if (auto fm = FileManifest::deserialize(*data)) {
            for (const auto& chunk : fm->chunks) {
                if (!chunk.hash.is_zero()) {
                    reachable.insert(chunk.hash);
                }
            }
        }
    }

    return reachable;
}

ManifestDiff diff_manifests(const Store& store, const Hash256& old_root, const Hash256& new_root) {
    ManifestDiff diff;
    diff_recursive(store, old_root, new_root, "", diff);
    return diff;
}

} // namespace bro::cas
