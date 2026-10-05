#include <brocas/hash.h>
#include <blake3.h>

#include <algorithm>
#include <array>
#include <cstring>
#include <fstream>
#include <ostream>

namespace bro::cas {

namespace {

constexpr char kHexChars[] = "0123456789abcdef";

int hex_val(char c) noexcept {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

blake3_hasher* as_blake3(uint8_t* state) noexcept {
    return reinterpret_cast<blake3_hasher*>(state);
}

const blake3_hasher* as_blake3(const uint8_t* state) noexcept {
    return reinterpret_cast<const blake3_hasher*>(state);
}

} // namespace

Hash256::Hash256(std::span<const uint8_t, kSize> src) noexcept {
    std::memcpy(bytes.data(), src.data(), kSize);
}

Hash256::Hash256(const uint8_t* src) noexcept {
    if (src != nullptr) {
        std::memcpy(bytes.data(), src, kSize);
    } else {
        bytes.fill(0);
    }
}

Hash256 Hash256::zero() noexcept {
    return Hash256();
}

bool Hash256::is_zero() const noexcept {
    return std::all_of(bytes.begin(), bytes.end(), [](uint8_t b) { return b == 0; });
}

std::string Hash256::to_hex() const {
    std::string out;
    out.resize(kSize * 2);
    for (size_t i = 0; i < kSize; ++i) {
        out[i * 2]     = kHexChars[(bytes[i] >> 4) & 0x0F];
        out[i * 2 + 1] = kHexChars[bytes[i] & 0x0F];
    }
    return out;
}

std::optional<Hash256> Hash256::from_hex(std::string_view hex) noexcept {
    if (hex.size() != kSize * 2) {
        return std::nullopt;
    }
    Hash256 out;
    for (size_t i = 0; i < kSize; ++i) {
        int hi = hex_val(hex[i * 2]);
        int lo = hex_val(hex[i * 2 + 1]);
        if (hi < 0 || lo < 0) {
            return std::nullopt;
        }
        out.bytes[i] = static_cast<uint8_t>((hi << 4) | lo);
    }
    return out;
}

std::ostream& operator<<(std::ostream& os, const Hash256& h) {
    return os << h.to_hex();
}

Hasher::Hasher() {
    static_assert(sizeof(blake3_hasher) <= kStateSize, "kStateSize too small for blake3_hasher");
    static_assert(alignof(blake3_hasher) <= alignof(Hasher), "Alignment mismatch");
    blake3_hasher_init(as_blake3(state_));
}

Hasher::~Hasher() = default;

Hasher::Hasher(const Hasher& other) {
    std::memcpy(state_, other.state_, sizeof(blake3_hasher));
}

Hasher& Hasher::operator=(const Hasher& other) {
    if (this != &other) {
        std::memcpy(state_, other.state_, sizeof(blake3_hasher));
    }
    return *this;
}

Hasher::Hasher(Hasher&& other) noexcept {
    std::memcpy(state_, other.state_, sizeof(blake3_hasher));
    other.reset();
}

Hasher& Hasher::operator=(Hasher&& other) noexcept {
    if (this != &other) {
        std::memcpy(state_, other.state_, sizeof(blake3_hasher));
        other.reset();
    }
    return *this;
}

void Hasher::update(const void* data, size_t size) {
    if (data != nullptr && size > 0) {
        blake3_hasher_update(as_blake3(state_), data, size);
    }
}

void Hasher::update(std::string_view sv) {
    update(sv.data(), sv.size());
}

void Hasher::update(std::span<const uint8_t> bytes) {
    update(bytes.data(), bytes.size());
}

Hash256 Hasher::finalize() const {
    blake3_hasher copy = *as_blake3(state_);
    Hash256 out;
    blake3_hasher_finalize(&copy, out.data(), Hash256::kSize);
    return out;
}

void Hasher::reset() {
    blake3_hasher_reset(as_blake3(state_));
}

Hash256 Hasher::hash(const void* data, size_t size) {
    Hasher h;
    h.update(data, size);
    return h.finalize();
}

Hash256 Hasher::hash(std::span<const uint8_t> bytes) {
    return hash(bytes.data(), bytes.size());
}

Hash256 Hasher::hash(std::string_view sv) {
    return hash(sv.data(), sv.size());
}

std::optional<Hash256> Hasher::hash_file(const std::filesystem::path& path) {
    std::ifstream file(path, std::ios::binary);
    if (!file.is_open()) {
        return std::nullopt;
    }
    Hasher h;
    std::array<char, 65536> buffer;
    while (file.read(buffer.data(), buffer.size()) || file.gcount() > 0) {
        h.update(buffer.data(), static_cast<size_t>(file.gcount()));
    }
    return h.finalize();
}

} // namespace bro::cas
