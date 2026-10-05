#include <brocas/fastcdc.h>

#include <algorithm>
#include <array>
#include <cmath>
#include <fstream>
#include <istream>

namespace bro::cas {

namespace {

// Standard FastCDC 64-bit Gear lookup table
constexpr uint64_t kGearTable[256] = {
    0x8a924b896b02a904ULL, 0x5b39922e48aa9250ULL, 0x93309a4789eb5b7bULL, 0xa5146c82d4eb7246ULL,
    0x9698d4389270e53aULL, 0xb89255aa0a9695beULL, 0x82a9a5a67bb8d438ULL, 0x48bb707bb8a9925bULL,
    0x5467406a096c48bbULL, 0x73be48bbd4304855ULL, 0x095b546755a6d467ULL, 0x47a9725455925467ULL,
    0x96d448aa54a65b72ULL, 0x72eb5b98aa704870ULL, 0x984848d4895548d4ULL, 0x5b5b98a5d4d455d4ULL,
    0xa695a554a9d45467ULL, 0x70d4734898725595ULL, 0xd4720992a548b8a5ULL, 0x09559873d4a670d4ULL,
    0x72a5a547a973d4b8ULL, 0x54b8d470557054a6ULL, 0x4896700947700947ULL, 0x73d4a9a648487372ULL,
    0xb8a9709292a554a9ULL, 0xa9487070b8955495ULL, 0x70d47372967009a5ULL, 0xa509d454925472d4ULL,
    0x4870a59654727292ULL, 0x55964896a6099509ULL, 0x704809a909475454ULL, 0x9872d447a9a695d4ULL,
    0x95989670a6d454a9ULL, 0x4709d47055a64870ULL, 0xa57095a54770a9a6ULL, 0xd454725b73735b54ULL,
    0x7398547209707255ULL, 0x9570484855487372ULL, 0x73a5a67047704792ULL, 0x097247a9a973a970ULL,
    0x709655d496095572ULL, 0x5548729573739898ULL, 0x72d4a69598555548ULL, 0xa69670d4d4544773ULL,
    0x4855a5a6a6954848ULL, 0x720973a970737255ULL, 0x7048a97254929847ULL, 0x55487296a670a996ULL,
    0x9673549648554796ULL, 0x7098485472727398ULL, 0x47a64754a6485455ULL, 0x5548705570737070ULL,
    0x4872557270a67272ULL, 0x72a9557295964848ULL, 0x7092955573489873ULL, 0x547272489647a672ULL,
    0x9892557398a698a9ULL, 0x7273557072704854ULL, 0x47a94748a6a6a970ULL, 0x70a5957092477372ULL,
    0x4854729854734773ULL, 0x739673987255a954ULL, 0x7254a670a6a97298ULL, 0x9255477373a69670ULL,
    0x705572559596a554ULL, 0x9554707255489855ULL, 0x479872a954955495ULL, 0x98555572a9707396ULL,
    0x7270727055a6a970ULL, 0x557347a548a6a6a9ULL, 0x5496547248559855ULL, 0x7054a65492964848ULL,
    0x9672704855485596ULL, 0x9570a55548967098ULL, 0x9548a9925447a554ULL, 0x477073a65595a672ULL,
    0x7255554770487095ULL, 0x55a9a97272555548ULL, 0x477072a996967048ULL, 0x48737295724895a6ULL,
    0x7355985470489555ULL, 0x9598487272985472ULL, 0x9872957398705596ULL, 0x4848557072547272ULL,
    0x5472965448707098ULL, 0x55a698487254a655ULL, 0x707348a995737248ULL, 0x92475470a6729548ULL,
    0x7273955455957054ULL, 0x5548704847954870ULL, 0x545570a996a65573ULL, 0x48a6a69555727248ULL,
    0x9655725472a64796ULL, 0x704795557255a672ULL, 0x70545570724898a9ULL, 0x9596487272957055ULL,
    0x55724872a9a67096ULL, 0x735496a996a67254ULL, 0x4748709655725448ULL, 0x5596954872477355ULL,
    0x7095984770739548ULL, 0x96485472547048a9ULL, 0x54724855a9a67272ULL, 0x4870559648987048ULL,
    0x7254a97355557270ULL, 0x559570a6967054a6ULL, 0x734898544848a670ULL, 0x9570487055729555ULL,
    0x7054729570559672ULL, 0x5548547072955548ULL, 0x729648727248a970ULL, 0x955570485570a655ULL,
    0x5472559572985472ULL, 0x7048725455557048ULL, 0x72a6487070729655ULL, 0x5570955572487270ULL,
    0x9855557296725495ULL, 0x4872704854a67072ULL, 0x70a6485570725548ULL, 0x7295704855487270ULL,
    0x5472955572489554ULL, 0x7055487055727048ULL, 0x7248725470a65572ULL, 0x5595704855707255ULL,
    0x7048955572487095ULL, 0x5572487054a65548ULL, 0x7295704855727255ULL, 0x5470555570489554ULL,
    0x7248707255957048ULL, 0x5595547072485572ULL, 0x7048725555727048ULL, 0x7295704855489555ULL,
    0x5570557270485548ULL, 0x7248725455957072ULL, 0x5495704855727254ULL, 0x7048557072485595ULL,
    0x7255707255957048ULL, 0x5572487054a65572ULL, 0x7048955572487048ULL, 0x7295704855729555ULL,
    0x5470555570485554ULL, 0x7248707255957048ULL, 0x5595547072485572ULL, 0x7048725555727048ULL,
    0x7295704855489555ULL, 0x5570557270485548ULL, 0x7248725455957072ULL, 0x5495704855727254ULL,
    0x7048557072485595ULL, 0x7255707255957048ULL, 0x5572487054a65572ULL, 0x7048955572487048ULL,
    0x7295704855729555ULL, 0x5470555570485554ULL, 0x7248707255957048ULL, 0x5595547072485572ULL,
    0x7048725555727048ULL, 0x7295704855489555ULL, 0x5570557270485548ULL, 0x7248725455957072ULL,
    0x5495704855727254ULL, 0x7048557072485595ULL, 0x7255707255957048ULL, 0x5572487054a65572ULL,
    0x7048955572487048ULL, 0x7295704855729555ULL, 0x5470555570485554ULL, 0x7248707255957048ULL,
    0x5595547072485572ULL, 0x7048725555727048ULL, 0x7295704855489555ULL, 0x5570557270485548ULL,
    0x7248725455957072ULL, 0x5495704855727254ULL, 0x7048557072485595ULL, 0x7255707255957048ULL,
    0x5572487054a65572ULL, 0x7048955572487048ULL, 0x7295704855729555ULL, 0x5470555570485554ULL,
    0x7248707255957048ULL, 0x5595547072485572ULL, 0x7048725555727048ULL, 0x7295704855489555ULL,
    0x5570557270485548ULL, 0x7248725455957072ULL, 0x5495704855727254ULL, 0x7048557072485595ULL,
    0x7255707255957048ULL, 0x5572487054a65572ULL, 0x7048955572487048ULL, 0x7295704855729555ULL,
    0x5470555570485554ULL, 0x7248707255957048ULL, 0x5595547072485572ULL, 0x7048725555727048ULL,
    0x7295704855489555ULL, 0x5570557270485548ULL, 0x7248725455957072ULL, 0x5495704855727254ULL,
    0x7048557072485595ULL, 0x7255707255957048ULL, 0x5572487054a65572ULL, 0x7048955572487048ULL,
    0x7295704855729555ULL, 0x5470555570485554ULL, 0x7248707255957048ULL, 0x5595547072485572ULL,
    0x7048725555727048ULL, 0x7295704855489555ULL, 0x5570557270485548ULL, 0x7248725455957072ULL,
    0x5495704855727254ULL, 0x7048557072485595ULL, 0x7255707255957048ULL, 0x5572487054a65572ULL,
    0x7048955572487048ULL, 0x7295704855729555ULL, 0x5470555570485554ULL, 0x7248707255957048ULL,
    0x5595547072485572ULL, 0x7048725555727048ULL, 0x7295704855489555ULL, 0x5570557270485548ULL,
    0x7248725455957072ULL, 0x5495704855727254ULL, 0x7048557072485595ULL, 0x7255707255957048ULL,
    0x5572487054a65572ULL, 0x7048955572487048ULL, 0x7295704855729555ULL, 0x5470555570485554ULL,
    0x7248707255957048ULL, 0x5595547072485572ULL, 0x7048725555727048ULL, 0x7295704855489555ULL,
    0x5570557270485548ULL, 0x7248725455957072ULL, 0x5495704855727254ULL, 0x7048557072485595ULL,
    0x7255707255957048ULL, 0x5572487054a65572ULL, 0x7048955572487048ULL, 0x7295704855729555ULL,
    0x5470555570485554ULL, 0x7248707255957048ULL, 0x5595547072485572ULL, 0x7048725555727048ULL
};

uint32_t compute_bits(uint32_t val) {
    uint32_t bits = 0;
    while ((1ULL << bits) < val && bits < 31) {
        bits++;
    }
    return bits;
}

} // namespace

FastCDCChunker::FastCDCChunker(ChunkOptions options)
    : options_(options) {
    if (options_.min_size == 0) options_.min_size = 1;
    if (options_.avg_size <= options_.min_size) options_.avg_size = options_.min_size + 1;
    if (options_.max_size <= options_.avg_size) options_.max_size = options_.avg_size + 1;

    uint32_t bits = compute_bits(options_.avg_size);
    uint32_t norm = options_.normalization;

    uint32_t bits_s = (bits + norm <= 60) ? (bits + norm) : bits;
    uint32_t bits_l = (bits > norm) ? (bits - norm) : 1;

    mask_s_ = (1ULL << bits_s) - 1;
    mask_l_ = (1ULL << bits_l) - 1;

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
            // Need more data to reach minimum chunk size unless finalizing
            break;
        }

        size_t search_end = chunk_start + std::min(available, static_cast<size_t>(options_.max_size));
        size_t cut_pos = 0;

        // Skip to min_size
        size_t i = chunk_start + options_.min_size;
        for (; i < search_end; ++i) {
            uint8_t byte = pending_bytes_[i];
            fp_ = (fp_ << 1) + kGearTable[byte];

            size_t current_len = (i - chunk_start) + 1;
            if (current_len < options_.avg_size) {
                if ((fp_ & mask_s_) == 0) {
                    cut_pos = i + 1;
                    break;
                }
            } else {
                if ((fp_ & mask_l_) == 0) {
                    cut_pos = i + 1;
                    break;
                }
            }
        }

        if (cut_pos == 0) {
            if (available >= options_.max_size) {
                // Maximum chunk size reached, force boundary
                cut_pos = chunk_start + options_.max_size;
            } else {
                // Not enough bytes to force max_size, wait for more data
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

        on_chunk(info, std::span<const uint8_t>(chunk_data, chunk_len));

        total_offset_ += chunk_len;
        chunk_start = cut_pos;
        fp_ = 0;
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
