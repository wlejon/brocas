#pragma once

#include <brocas/hash.h>

#include <cstddef>
#include <cstdint>
#include <optional>
#include <ostream>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace bro::cas {

enum class MessageType : uint8_t {
    Handshake = 1,
    HandshakeAck = 2,
    ManifestRequest = 3,
    ManifestResponse = 4,
    HaveQuery = 5,
    HaveResponse = 6,
    WantChunks = 7,
    ChunkData = 8,
    Complete = 9,
    Error = 10
};

const char* to_string(MessageType type) noexcept;

inline std::ostream& operator<<(std::ostream& os, MessageType type) {
    return os << to_string(type);
}

struct Frame {
    MessageType type = MessageType::Handshake;
    std::vector<uint8_t> payload;

    auto operator<=>(const Frame& other) const = default;
    bool operator==(const Frame& other) const = default;
};

// Message structures
struct HandshakeMsg {
    uint16_t version = 1;
    uint32_t capabilities = 0;
    std::string client_id;

    std::vector<uint8_t> serialize() const;
    static std::optional<HandshakeMsg> deserialize(std::span<const uint8_t> payload);
};

struct HandshakeAckMsg {
    uint16_t version = 1;
    uint32_t capabilities = 0;

    std::vector<uint8_t> serialize() const;
    static std::optional<HandshakeAckMsg> deserialize(std::span<const uint8_t> payload);
};

struct ManifestRequestMsg {
    Hash256 root_hash;

    std::vector<uint8_t> serialize() const;
    static std::optional<ManifestRequestMsg> deserialize(std::span<const uint8_t> payload);
};

struct ManifestResponseMsg {
    Hash256 root_hash;
    bool found = false;
    std::vector<uint8_t> data;

    std::vector<uint8_t> serialize() const;
    static std::optional<ManifestResponseMsg> deserialize(std::span<const uint8_t> payload);
};

struct HaveQueryMsg {
    std::vector<Hash256> hashes;

    std::vector<uint8_t> serialize() const;
    static std::optional<HaveQueryMsg> deserialize(std::span<const uint8_t> payload);
};

struct HaveResponseMsg {
    std::vector<uint8_t> have_flags; // 1 if present, 0 if absent

    std::vector<uint8_t> serialize() const;
    static std::optional<HaveResponseMsg> deserialize(std::span<const uint8_t> payload);
};

struct WantChunksMsg {
    std::vector<Hash256> hashes;

    std::vector<uint8_t> serialize() const;
    static std::optional<WantChunksMsg> deserialize(std::span<const uint8_t> payload);
};

struct ChunkDataMsg {
    Hash256 hash;
    std::vector<uint8_t> data;

    std::vector<uint8_t> serialize() const;
    static std::optional<ChunkDataMsg> deserialize(std::span<const uint8_t> payload);
};

struct CompleteMsg {
    uint32_t status = 0; // 0 for success
    std::string message;

    std::vector<uint8_t> serialize() const;
    static std::optional<CompleteMsg> deserialize(std::span<const uint8_t> payload);
};

struct ErrorMsg {
    uint32_t code = 0;
    std::string message;

    std::vector<uint8_t> serialize() const;
    static std::optional<ErrorMsg> deserialize(std::span<const uint8_t> payload);
};

uint32_t crc32(std::span<const uint8_t> data);

class WireFraming {
public:
    static constexpr uint32_t kMagic = 0x42524341; // "BRCA"
    static constexpr size_t kHeaderSize = 9; // 4 magic + 1 type + 4 len
    static constexpr size_t kTrailerSize = 4; // 4 crc32
    static constexpr size_t kMaxPayload = 64 * 1024 * 1024; // 64 MiB

    static std::vector<uint8_t> encode(MessageType type, std::span<const uint8_t> payload);
    static std::vector<uint8_t> encode(const Frame& frame);

    // Feed bytes into parser
    void feed(std::span<const uint8_t> bytes);
    void feed(const void* data, size_t size);

    // Pop the next complete and verified frame, or nullopt if need more data.
    // If corruption is encountered, returns nullopt and skips invalid data.
    std::optional<Frame> pop_frame();

    void reset();
    size_t buffered_size() const noexcept { return buffer_.size(); }

private:
    std::vector<uint8_t> buffer_;
};

} // namespace bro::cas
