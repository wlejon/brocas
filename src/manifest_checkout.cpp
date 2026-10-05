#include <brocas/manifest.h>

#include <chrono>
#include <fstream>
#include <system_error>

namespace bro::cas {

namespace {

void restore_file_mtime(const std::filesystem::path& p, uint64_t unix_secs) {
    if (unix_secs == 0) return;
    std::error_code ec;
    auto sys_tp = std::chrono::system_clock::time_point(std::chrono::seconds(unix_secs));
    auto now_sys = std::chrono::system_clock::now();
    auto diff = sys_tp - now_sys;
    auto file_tp = std::filesystem::file_time_type::clock::now() +
                   std::chrono::duration_cast<std::filesystem::file_time_type::duration>(diff);
    std::filesystem::last_write_time(p, file_tp, ec);
}

void restore_file_perms(const std::filesystem::path& p, uint32_t mode) {
    using std::filesystem::perms;
    perms perm = perms::none;
    if (mode & 0400) perm |= perms::owner_read;
    if (mode & 0200) perm |= perms::owner_write;
    if (mode & 0100) perm |= perms::owner_exec;
    if (mode & 0040) perm |= perms::group_read;
    if (mode & 0020) perm |= perms::group_write;
    if (mode & 0010) perm |= perms::group_exec;
    if (mode & 0004) perm |= perms::others_read;
    if (mode & 0002) perm |= perms::others_write;
    if (mode & 0001) perm |= perms::others_exec;

    std::error_code ec;
    std::filesystem::permissions(p, perm, std::filesystem::perm_options::replace, ec);
}

} // namespace

CheckoutStats checkout_directory(const Store& store, const Hash256& root_hash,
                                 const std::filesystem::path& target_dir,
                                 CheckoutOptions options) {
    CheckoutStats stats;
    std::error_code ec;
    std::filesystem::create_directories(target_dir, ec);

    auto manifest_data = store.read_chunk(root_hash);
    if (!manifest_data) {
        return stats;
    }

    auto manifest = Manifest::deserialize(*manifest_data);
    if (!manifest) {
        return stats;
    }

    for (const auto& entry : manifest->entries) {
        auto dest = target_dir / entry.name;

        if (entry.kind == EntryKind::Directory) {
            std::filesystem::create_directories(dest, ec);
            stats.dirs_created++;

            CheckoutStats sub_stats = checkout_directory(store, entry.hash, dest, options);
            stats.files_created += sub_stats.files_created;
            stats.dirs_created += sub_stats.dirs_created;
            stats.symlinks_created += sub_stats.symlinks_created;
            stats.total_bytes += sub_stats.total_bytes;

            if (options.restore_permissions) {
                restore_file_perms(dest, entry.mode);
            }
            if (options.restore_mtime) {
                restore_file_mtime(dest, entry.mtime);
            }
        } else if (entry.kind == EntryKind::Regular) {
            auto chunk_data = store.read_chunk(entry.hash);
            if (chunk_data) {
                std::ofstream f(dest, std::ios::binary | std::ios::trunc);
                if (!chunk_data->empty()) {
                    f.write(reinterpret_cast<const char*>(chunk_data->data()),
                            static_cast<std::streamsize>(chunk_data->size()));
                }
                f.close();

                stats.files_created++;
                stats.total_bytes += entry.size;

                if (options.restore_permissions) {
                    restore_file_perms(dest, entry.mode);
                }
                if (options.restore_mtime) {
                    restore_file_mtime(dest, entry.mtime);
                }
            }
        } else if (entry.kind == EntryKind::MultiChunkRegular) {
            auto fm_data = store.read_chunk(entry.hash);
            if (fm_data) {
                auto fm = FileManifest::deserialize(*fm_data);
                if (fm) {
                    std::ofstream f(dest, std::ios::binary | std::ios::trunc);
                    for (const auto& chunk : fm->chunks) {
                        auto chunk_data = store.read_chunk(chunk.hash);
                        if (chunk_data && !chunk_data->empty()) {
                            f.write(reinterpret_cast<const char*>(chunk_data->data()),
                                    static_cast<std::streamsize>(chunk_data->size()));
                        }
                    }
                    f.close();

                    stats.files_created++;
                    stats.total_bytes += entry.size;

                    if (options.restore_permissions) {
                        restore_file_perms(dest, entry.mode);
                    }
                    if (options.restore_mtime) {
                        restore_file_mtime(dest, entry.mtime);
                    }
                }
            }
        } else if (entry.kind == EntryKind::Symlink) {
            if (options.restore_symlinks) {
                std::filesystem::remove(dest, ec);
                std::filesystem::create_symlink(entry.symlink_target, dest, ec);
            }
            stats.symlinks_created++;
        }
    }

    return stats;
}

} // namespace bro::cas
