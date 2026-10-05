#include <brocas/manifest.h>

#include <chrono>
#include <fstream>
#include <system_error>

namespace bro::cas {

namespace {

uint64_t to_unix_seconds(std::filesystem::file_time_type ftime) {
    auto now_sys = std::chrono::system_clock::now();
    auto now_file = std::filesystem::file_time_type::clock::now();
    auto diff = ftime - now_file;
    auto est_sys = now_sys + std::chrono::duration_cast<std::chrono::system_clock::duration>(diff);
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(est_sys.time_since_epoch()).count());
}

uint32_t to_unix_mode(std::filesystem::perms p, bool is_dir) {
    uint32_t mode = 0;
    using std::filesystem::perms;
    if ((p & perms::owner_read) != perms::none)   mode |= 0400;
    if ((p & perms::owner_write) != perms::none)  mode |= 0200;
    if ((p & perms::owner_exec) != perms::none)   mode |= 0100;
    if ((p & perms::group_read) != perms::none)   mode |= 0040;
    if ((p & perms::group_write) != perms::none)  mode |= 0020;
    if ((p & perms::group_exec) != perms::none)   mode |= 0010;
    if ((p & perms::others_read) != perms::none)  mode |= 0004;
    if ((p & perms::others_write) != perms::none) mode |= 0002;
    if ((p & perms::others_exec) != perms::none)  mode |= 0001;

    if (mode == 0) {
        mode = is_dir ? 0755 : 0644;
    }
    return mode;
}

} // namespace

Hash256 ingest_directory(Store& store, const std::filesystem::path& dir, IngestOptions options) {
    Manifest manifest;
    std::error_code ec;

    if (!std::filesystem::exists(dir, ec) || !std::filesystem::is_directory(dir, ec)) {
        manifest.sort();
        auto data = manifest.serialize();
        return store.put_chunk(data);
    }

    for (const auto& entry : std::filesystem::directory_iterator(dir, std::filesystem::directory_options::none, ec)) {
        if (ec) break;

        std::string filename = entry.path().filename().string();
        if (filename.empty() || filename == "." || filename == "..") {
            continue;
        }

        bool is_symlink = entry.is_symlink(ec);
        if (is_symlink) {
            auto target = std::filesystem::read_symlink(entry.path(), ec);
            std::string target_str = target.string();
            Hash256 target_hash = Hasher::hash(target_str);

            FileEntry fe;
            fe.name = filename;
            fe.kind = EntryKind::Symlink;
            fe.size = 0;
            fe.mode = 0777;
            fe.mtime = to_unix_seconds(entry.last_write_time(ec));
            fe.symlink_target = target_str;
            fe.hash = target_hash;

            manifest.add_entry(std::move(fe));
            continue;
        }

        bool is_dir = entry.is_directory(ec);
        if (is_dir) {
            Hash256 sub_hash = ingest_directory(store, entry.path(), options);

            FileEntry fe;
            fe.name = filename;
            fe.kind = EntryKind::Directory;
            fe.size = 0;
            fe.mode = to_unix_mode(entry.status(ec).permissions(), true);
            fe.mtime = to_unix_seconds(entry.last_write_time(ec));
            fe.hash = sub_hash;

            manifest.add_entry(std::move(fe));
            continue;
        }

        bool is_regular = entry.is_regular_file(ec);
        if (is_regular) {
            uint64_t file_size = entry.file_size(ec);
            uint32_t mode = to_unix_mode(entry.status(ec).permissions(), false);
            uint64_t mtime = to_unix_seconds(entry.last_write_time(ec));

            if (file_size <= options.chunk_threshold) {
                // Single chunk regular file
                std::ifstream f(entry.path(), std::ios::binary);
                std::vector<uint8_t> contents(static_cast<size_t>(file_size));
                if (file_size > 0) {
                    f.read(reinterpret_cast<char*>(contents.data()), static_cast<std::streamsize>(file_size));
                }

                Hash256 chunk_hash = store.put_chunk(contents);

                FileEntry fe;
                fe.name = filename;
                fe.kind = EntryKind::Regular;
                fe.size = file_size;
                fe.mode = mode;
                fe.mtime = mtime;
                fe.hash = chunk_hash;

                manifest.add_entry(std::move(fe));
            } else {
                // Multi-chunk regular file chunked with FastCDC
                FileManifest file_manifest;
                file_manifest.total_size = file_size;

                std::ifstream f(entry.path(), std::ios::binary);
                FastCDCChunker chunker(options.chunk_options);
                std::vector<char> read_buf(65536);

                while (f.read(read_buf.data(), read_buf.size()) || f.gcount() > 0) {
                    chunker.update(read_buf.data(), static_cast<size_t>(f.gcount()),
                                   [&](const ChunkInfo& info, std::span<const uint8_t> data) {
                                       store.write_chunk(info.hash, data);
                                       file_manifest.chunks.push_back(info);
                                   });
                }
                chunker.finalize([&](const ChunkInfo& info, std::span<const uint8_t> data) {
                    store.write_chunk(info.hash, data);
                    file_manifest.chunks.push_back(info);
                });

                auto serialized_file_manifest = file_manifest.serialize();
                Hash256 file_manifest_hash = store.put_chunk(serialized_file_manifest);

                FileEntry fe;
                fe.name = filename;
                fe.kind = EntryKind::MultiChunkRegular;
                fe.size = file_size;
                fe.mode = mode;
                fe.mtime = mtime;
                fe.hash = file_manifest_hash;

                manifest.add_entry(std::move(fe));
            }
        }
    }

    manifest.sort();
    auto serialized_manifest = manifest.serialize();
    return store.put_chunk(serialized_manifest);
}

} // namespace bro::cas
