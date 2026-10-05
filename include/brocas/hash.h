#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <iosfwd>
#include <optional>
#include <span>
#include <string>
#include <string_view>

namespace bro::cas {

struct Hash256 {
    static constexpr size_t kSize = 32;
    std::array<uint8_t, kSize> bytes{};

    constexpr Hash256() noexcept = default;
    explicit Hash256(std::span<const uint8_t, kSize> src) noexcept;
    explicit Hash256(const uint8_t* src) noexcept;

    static Hash256 zero() noexcept;
    bool is_zero() const noexcept;

    std::string to_hex() const;
    static std::optional<Hash256> from_hex(std::string_view hex) noexcept;

    const uint8_t* data() const noexcept { return bytes.data(); }
    uint8_t* data() noexcept { return bytes.data(); }
    constexpr size_t size() const noexcept { return kSize; }

    const uint8_t* begin() const noexcept { return bytes.data(); }
    const uint8_t* end() const noexcept { return bytes.data() + kSize; }
    uint8_t* begin() noexcept { return bytes.data(); }
    uint8_t* end() noexcept { return bytes.data() + kSize; }

    uint8_t operator[](size_t idx) const noexcept { return bytes[idx]; }
    uint8_t& operator[](size_t idx) noexcept { return bytes[idx]; }

    std::span<const uint8_t> as_span() const noexcept {
        return {bytes.data(), kSize};
    }

    auto operator<=>(const Hash256& other) const = default;
    bool operator==(const Hash256& other) const = default;

    friend std::ostream& operator<<(std::ostream& os, const Hash256& h);
};

class Hasher {
public:
    Hasher();
    ~Hasher();

    Hasher(const Hasher& other);
    Hasher& operator=(const Hasher& other);
    Hasher(Hasher&& other) noexcept;
    Hasher& operator=(Hasher&& other) noexcept;

    void update(const void* data, size_t size);
    void update(std::string_view sv);
    void update(std::span<const uint8_t> bytes);

    Hash256 finalize() const;
    void reset();

    static Hash256 hash(const void* data, size_t size);
    static Hash256 hash(std::span<const uint8_t> bytes);
    static Hash256 hash(std::string_view sv);
    static std::optional<Hash256> hash_file(const std::filesystem::path& path);

private:
    static constexpr size_t kStateSize = 2048;
    alignas(8) uint8_t state_[kStateSize];
};

} // namespace bro::cas

namespace std {
template <>
struct hash<bro::cas::Hash256> {
    size_t operator()(const bro::cas::Hash256& h) const noexcept {
        size_t result = 0;
        std::memcpy(&result, h.data(), sizeof(size_t));
        return result;
    }
};
} // namespace std
