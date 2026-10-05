#include <brocas/fastcdc.h>

#include <algorithm>
#include <array>
#include <cmath>
#include <fstream>
#include <istream>

namespace bro::cas {

namespace {

// Canonical FastCDC 64-bit Gear lookup table (MD5 digest of 0..255, high 8 bytes)
constexpr uint64_t kGearTable[256] = {
    0x3b5d3c7d207e37dcULL, 0x784d68ba91123086ULL, 0xcd52880f882e7298ULL, 0xeacf8e4e19fdcca7ULL,
    0xc31f385dfbd1632bULL, 0x1d5f27001e25abe6ULL, 0x83130bde3c9ad991ULL, 0xc4b225676e9b7649ULL,
    0xaa329b29e08eb499ULL, 0xb67fcbd21e577d58ULL, 0x0027baaada2acf6bULL, 0xe3ef2d5ac73c2226ULL,
    0x0890f24d6ed312b7ULL, 0xa809e036851d7c7eULL, 0xf0a6fe5e0013d81bULL, 0x1d026304452cec14ULL,
    0x03864632648e248fULL, 0xcdaacf3dcd92b9b4ULL, 0xf5e012e63c187856ULL, 0x8862f9d3821c00b6ULL,
    0xa82f7338750f6f8aULL, 0x1e583dc6c1cb0b6fULL, 0x7a3145b69743a7f1ULL, 0xabb20fee404807ebULL,
    0xb14b3cfe07b83a5dULL, 0xb9dc27898adb9a0fULL, 0x3703f5e91baa62beULL, 0xcf0bb866815f7d98ULL,
    0x3d9867c41ea9dcd3ULL, 0x1be1fa65442bf22cULL, 0x14300da4c55631d9ULL, 0xe698e9cbc6545c99ULL,
    0x4763107ec64e92a5ULL, 0xc65821fc65696a24ULL, 0x76196c064822f0b7ULL, 0x485be841f3525e01ULL,
    0xf652bc9c85974ff5ULL, 0xcad8352face9e3e9ULL, 0x2a6ed1dceb35e98eULL, 0xc6f483badc11680fULL,
    0x3cfd8c17e9cf12f1ULL, 0x89b83c5e2ea56471ULL, 0xae665cfd24e392a9ULL, 0xec33c4e504cb8915ULL,
    0x3fb9b15fc9fe7451ULL, 0xd7fd1fd1945f2195ULL, 0x31ade0853443efd8ULL, 0x255efc9863e1e2d2ULL,
    0x10eab6008d5642cfULL, 0x46f04863257ac804ULL, 0xa52dc42a789a27d3ULL, 0xdaaadf9ce77af565ULL,
    0x6b479cd53d87febbULL, 0x6309e2d3f93db72fULL, 0xc5738ffbaa1ff9d6ULL, 0x6bd57f3f25af7968ULL,
    0x67605486d90d0a4aULL, 0xe14d0b9663bfbdaeULL, 0xb7bbd8d816eb0414ULL, 0xdef8a4f16b35a116ULL,
    0xe7932d85aaaffed6ULL, 0x08161cbae90cfd48ULL, 0x855507beb294f08bULL, 0x91234ea6ffd399b2ULL,
    0xad70cf4b2435f302ULL, 0xd289a97565bc2d27ULL, 0x8e558437ffca99deULL, 0x96d2704b7115c040ULL,
    0x0889bbcdfc660e41ULL, 0x5e0d4e67dc92128dULL, 0x72a9f8917063ed97ULL, 0x438b69d409e016e3ULL,
    0xdf4fed8a5d8a4397ULL, 0x00f41dcf41d403f7ULL, 0x4814eb038e52603fULL, 0x9dafbacc58e2d651ULL,
    0xfe2f458e4be170afULL, 0x4457ec414df6a940ULL, 0x06e62f1451123314ULL, 0xbd1014d173ba92ccULL,
    0xdef318e25ed57760ULL, 0x9fea0de9dfca8525ULL, 0x459de1e76c20624bULL, 0xaeec189617e2d666ULL,
    0x126a2c06ab5a83cbULL, 0xb1321532360f6132ULL, 0x65421503dbb40123ULL, 0x2d67c287ea089ab3ULL,
    0x6c93bff5a56bd6b6ULL, 0x4ffb2036cab6d98dULL, 0xce7b785b1be7ad4fULL, 0xedb42ef6189fd163ULL,
    0xdc905288703988f6ULL, 0x365f9c1d2c691884ULL, 0xc640583680d99bfeULL, 0x3cd4624c07593ec6ULL,
    0x7f1ea8d85d7c5805ULL, 0x014842d480b57149ULL, 0x0b649bcb5a828688ULL, 0xbcd5708ed79b18f0ULL,
    0xe987c862fbd2f2f0ULL, 0x982731671f0cd82cULL, 0xbaf13e8b16d8c063ULL, 0x8ea3109cbd951bbaULL,
    0xd141045bfb385cadULL, 0x2acbc1a0af1f7d30ULL, 0xe6444d89df03bfdfULL, 0xa18cc771b8188ff9ULL,
    0x9834429db01c39bbULL, 0x214add07fe086a1fULL, 0x8f07c19b1f6b3ff9ULL, 0x56a297b1bf4ffe55ULL,
    0x94d558e493c54fc7ULL, 0x40bfc24c764552cbULL, 0x931a706f8a8520cbULL, 0x32229d322935bd52ULL,
    0x2560d0f5dc4fefafULL, 0x9dbcc48355969bb6ULL, 0x0fd81c3985c0b56aULL, 0xe03817e1560f2bdaULL,
    0xc1bb4f81d892b2d5ULL, 0xb0c4864f4e28d2d7ULL, 0x3ecc49f9d9d6c263ULL, 0x51307e99b52ba65eULL,
    0x8af2b688da84a752ULL, 0xf5d72523b91b20b6ULL, 0x6d95ff1ff4634806ULL, 0x562f21555458339aULL,
    0xc0ce47f889336346ULL, 0x487823e5089b40d8ULL, 0xe4727c7ebc6d9592ULL, 0x5a8f7277e94970baULL,
    0xfca2f406b1c8bb50ULL, 0x5b1f8a95f1791070ULL, 0xd304af9fc9028605ULL, 0x5440ab7fc930e748ULL,
    0x312d25fbca2ab5a1ULL, 0x10f4a4b234a4d575ULL, 0x90301d55047e7473ULL, 0x3b6372886c61591eULL,
    0x293402b77c444e06ULL, 0x451f34a4d3e97dd7ULL, 0x3158d814d81bc57bULL, 0x034942425b9bda69ULL,
    0xe2032ff9e532d9bbULL, 0x62ae066b8b2179e5ULL, 0x9545e10c2f8d71d8ULL, 0x7ff7483eb2d23fc0ULL,
    0x00945fcebdc98d86ULL, 0x8764bbbe99b26ca2ULL, 0x1b1ec62284c0bfc3ULL, 0x58e0fcc4f0aa362bULL,
    0x5f4abefa878d458dULL, 0xfd74ac2f9607c519ULL, 0xa4e3fb37df8cbfa9ULL, 0xbf697e43cac574e5ULL,
    0x86f14a3f68f4cd53ULL, 0x24a23d076f1ce522ULL, 0xe725cd8048868cc8ULL, 0xbf3c729eb2464362ULL,
    0xd8f6cd57b3cc1ed8ULL, 0x6329e52425541577ULL, 0x62aa688ad5ae1ac0ULL, 0x0a242566269bf845ULL,
    0x168b1a4753aca74bULL, 0xf789afefff2e7e3cULL, 0x6c3362093b6fccdbULL, 0x4ce8f50bd28c09b2ULL,
    0x006a2db95ae8aa93ULL, 0x975b0d623c3d1a8cULL, 0x18605d3935338c5bULL, 0x5bb6f6136cad3c71ULL,
    0x0f53a20701f8d8a6ULL, 0xab8c5ad2e7e93c67ULL, 0x40b5ac5127acaa29ULL, 0x8c7bf63c2075895fULL,
    0x78bd9f7e014a805cULL, 0xb2c9e9f4f9c8c032ULL, 0xefd6049827eb91f3ULL, 0x2be459f482c16fbdULL,
    0xd92ce0c5745aaa8cULL, 0x0aaa8fb298d965b9ULL, 0x2b37f92c6c803b15ULL, 0x8c54a5e94e0f0e78ULL,
    0x95f9b6e90c0a3032ULL, 0xe7939faa436c7874ULL, 0xd16bfe8f6a8a40c9ULL, 0x44982b86263fd2faULL,
    0xe285fb39f984e583ULL, 0x779a8df72d7619d3ULL, 0xf2d79a8de8d5dd1eULL, 0xd1037354d66684e2ULL,
    0x004c82a4e668a8e5ULL, 0x31d40a7668b044e6ULL, 0xd70578538bd02c11ULL, 0xdb45431078c5f482ULL,
    0x977121bb7f6a51adULL, 0x73d5ccbd34eff8ddULL, 0xe437a07d356e17cdULL, 0x47b2782043c95627ULL,
    0x9fb251413e41d49aULL, 0xccd70b60652513d3ULL, 0x1c95b31e8a1b49b2ULL, 0xcae73dfd1bcb4c1bULL,
    0x34d98331b1f5b70fULL, 0x784e39f22338d92fULL, 0x18613d4a064df420ULL, 0xf1d8dae25f0bcebeULL,
    0x33f77c15ae855efcULL, 0x3c88b3b912eb109cULL, 0x956a2ec96bafeea5ULL, 0x1aa005b5e0ad0e87ULL,
    0x5500d70527c4bb8eULL, 0xe36c57196421cc44ULL, 0x13c4d286cc36ee39ULL, 0x5654a23d818b2a81ULL,
    0x77b1dc13d161abdcULL, 0x734f44de5f8d5eb5ULL, 0x60717e174a6c89a2ULL, 0xd47d9649266a211eULL,
    0x5b13a4322bb69e90ULL, 0xf7669609f8b5fc3cULL, 0x21e6ac55bedcdac9ULL, 0x9b56b62b61166deaULL,
    0xf48f66b939797e9cULL, 0x35f332f9c0e6ae9aULL, 0xcc733f6a9a878db0ULL, 0x3da161e41cc108c2ULL,
    0xb7d74ae535914d51ULL, 0x4d493b0b11d36469ULL, 0xce264d1dfba9741aULL, 0xa9d1f2dc7436dc06ULL,
    0x70738016604c2a27ULL, 0x231d36e96e93f3d5ULL, 0x7666881197838d19ULL, 0x4a2a83090aaad40cULL,
    0xf1e761591668b35dULL, 0x7363236497f730a7ULL, 0x301080e37379dd4dULL, 0x502dea2971827042ULL,
    0xc2c5eb858f32625fULL, 0x786afb9edfafbdffULL, 0xdaee0d868490b2a4ULL, 0x617366b3268609f6ULL,
    0xae0e35a0fe46173eULL, 0xd1a07de93e824f11ULL, 0x079b8b115ea4cca8ULL, 0x93a99274558faebbULL,
    0xfb1e6e22e08a03b3ULL, 0xea635fdba3698dd0ULL, 0xcf53659328503a5cULL, 0xcde3b31e6fd5d780ULL,
    0x8e3e4221d3614413ULL, 0xef14d0d86bf1a22cULL, 0xe1d830d3f16c5ddbULL, 0xaabd2b2a451504e1ULL
};

// Canonical FastCDC 2016 cut-point test masks (destor repository / fastcdc paper)
constexpr uint64_t kFastCDCMasks[26] = {
    0,                  // padding
    0,                  // padding
    0,                  // padding
    0,                  // padding
    0,                  // padding
    0x0000000001804110ULL, // unused except for NC 3
    0x0000000001803110ULL, // 64B
    0x0000000018035100ULL, // 128B
    0x0000001800035300ULL, // 256B
    0x0000019000353000ULL, // 512B
    0x0000590003530000ULL, // 1KB
    0x0000d90003530000ULL, // 2KB
    0x0000d90103530000ULL, // 4KB
    0x0000d90303530000ULL, // 8KB
    0x0000d90313530000ULL, // 16KB
    0x0000d90f03530000ULL, // 32KB
    0x0000d90303537000ULL, // 64KB
    0x0000d90703537000ULL, // 128KB
    0x0000d90707537000ULL, // 256KB
    0x0000d91707537000ULL, // 512KB
    0x0000d91747537000ULL, // 1MB
    0x0000d91767537000ULL, // 2MB
    0x0000d93767537000ULL, // 4MB
    0x0000d93777537000ULL, // 8MB
    0x0000d93777577000ULL, // 16MB
    0x0000db3777577000ULL  // unused except for NC 3
};

uint32_t logarithm2(uint32_t val) {
    return static_cast<uint32_t>(std::round(std::log2(static_cast<double>(val))));
}

} // namespace

FastCDCChunker::FastCDCChunker(ChunkOptions options)
    : options_(options) {
    if (options_.min_size == 0) options_.min_size = 64;
    if (options_.avg_size <= options_.min_size) options_.avg_size = options_.min_size + 1;
    if (options_.max_size <= options_.avg_size) options_.max_size = options_.avg_size + 1;

    uint32_t bits = logarithm2(options_.avg_size);
    uint32_t norm = options_.normalization;

    size_t idx_s = std::min<size_t>(25, bits + norm);
    size_t idx_l = (bits >= norm + 6) ? (bits - norm) : 6;

    mask_s_ = kFastCDCMasks[idx_s];
    mask_l_ = kFastCDCMasks[idx_l];

    pending_bytes_.reserve(options_.max_size * 2);
}

void FastCDCChunker::reset() {
    fp_ = 0;
    total_offset_ = 0;
    pending_bytes_.clear();
}

void FastCDCChunker::update(const void* data, size_t size,
                            const std::function<void(const ChunkInfo&, std::span<const uint8_t>)>& on_chunk) {
    if (data == nullptr || size == 0) return;

    const uint8_t* ptr = static_cast<const uint8_t*>(data);
    pending_bytes_.insert(pending_bytes_.end(), ptr, ptr + size);

    size_t chunk_start = 0;
    while (chunk_start < pending_bytes_.size()) {
        size_t available = pending_bytes_.size() - chunk_start;
        if (available < options_.min_size) {
            break;
        }

        size_t limit = std::min(available, static_cast<size_t>(options_.max_size));
        size_t center = std::min(limit, static_cast<size_t>(options_.avg_size));
        size_t cut_pos = 0;
        uint64_t cut_fp = 0;

        uint64_t fp = 0;
        size_t i = options_.min_size;
        for (; i < center; ++i) {
            uint8_t byte = pending_bytes_[chunk_start + i];
            fp = (fp << 1) + kGearTable[byte];
            if ((fp & mask_s_) == 0) {
                cut_pos = chunk_start + i;
                cut_fp = fp;
                break;
            }
        }

        if (cut_pos == 0) {
            for (; i < limit; ++i) {
                uint8_t byte = pending_bytes_[chunk_start + i];
                fp = (fp << 1) + kGearTable[byte];
                if ((fp & mask_l_) == 0) {
                    cut_pos = chunk_start + i;
                    cut_fp = fp;
                    break;
                }
            }
        }

        if (cut_pos == 0) {
            if (available >= options_.max_size) {
                cut_pos = chunk_start + options_.max_size;
                cut_fp = fp;
            } else {
                break;
            }
        }

        size_t chunk_len = cut_pos - chunk_start;
        const uint8_t* chunk_data = pending_bytes_.data() + chunk_start;
        Hash256 chunk_hash = Hasher::hash(chunk_data, chunk_len);

        ChunkInfo info;
        info.hash = chunk_hash;
        info.offset = total_offset_;
        info.size = static_cast<uint32_t>(chunk_len);
        info.gear_hash = cut_fp;

        on_chunk(info, std::span<const uint8_t>(chunk_data, chunk_len));

        total_offset_ += chunk_len;
        chunk_start = cut_pos;
    }

    if (chunk_start > 0) {
        pending_bytes_.erase(pending_bytes_.begin(), pending_bytes_.begin() + chunk_start);
    }
}

void FastCDCChunker::finalize(const std::function<void(const ChunkInfo&, std::span<const uint8_t>)>& on_chunk) {
    if (!pending_bytes_.empty()) {
        size_t rem = pending_bytes_.size();
        Hash256 chunk_hash = Hasher::hash(pending_bytes_.data(), rem);

        ChunkInfo info;
        info.hash = chunk_hash;
        info.offset = total_offset_;
        info.size = static_cast<uint32_t>(rem);
        info.gear_hash = 0;

        on_chunk(info, std::span<const uint8_t>(pending_bytes_.data(), rem));

        total_offset_ += rem;
        pending_bytes_.clear();
        fp_ = 0;
    }
}

std::vector<ChunkInfo> chunk_buffer(const void* data, size_t size, ChunkOptions options) {
    std::vector<ChunkInfo> chunks;
    FastCDCChunker chunker(options);
    chunker.update(data, size, [&](const ChunkInfo& info, std::span<const uint8_t>) {
        chunks.push_back(info);
    });
    chunker.finalize([&](const ChunkInfo& info, std::span<const uint8_t>) {
        chunks.push_back(info);
    });
    return chunks;
}

std::vector<ChunkInfo> chunk_buffer(std::span<const uint8_t> data, ChunkOptions options) {
    return chunk_buffer(data.data(), data.size(), options);
}

std::vector<ChunkInfo> chunk_file(const std::filesystem::path& path, ChunkOptions options) {
    std::vector<ChunkInfo> chunks;
    std::ifstream file(path, std::ios::binary);
    if (!file.is_open()) {
        return chunks;
    }
    chunk_stream(file, [&](const ChunkInfo& info, std::span<const uint8_t>) {
        chunks.push_back(info);
    }, options);
    return chunks;
}

void chunk_stream(std::istream& is,
                  const std::function<void(const ChunkInfo&, std::span<const uint8_t>)>& on_chunk,
                  ChunkOptions options) {
    FastCDCChunker chunker(options);
    std::array<char, 65536> buffer;
    while (is.read(buffer.data(), buffer.size()) || is.gcount() > 0) {
        chunker.update(buffer.data(), static_cast<size_t>(is.gcount()), on_chunk);
    }
    chunker.finalize(on_chunk);
}

} // namespace bro::cas
