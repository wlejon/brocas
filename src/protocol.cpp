#include <brocas/protocol.h>

#include <algorithm>
#include <array>
#include <cstring>

namespace bro::cas {

namespace {

const std::array<uint32_t, 256>& get_crc32_table() {
    static const auto table = [] {
        std::array<uint32_t, 256> t{};
        for (uint32_t i = 0; i < 256; ++i) {
            uint32_t c = i;
            for (int j = 0; j < 8; ++j) {
                c = (c & 1) ? (0xEDB88320L ^ (c >> 1)) : (c >> 1);
            }
            t[i] = c;
        }
        return t;
    }();
    return table;
}

void write_u16(std::vector<uint8_t>& buf, uint16_t val) {
    buf.push_back(static_cast<uint8_t>(val & 0xFF));
    buf.push_back(static_cast<uint8_t>((val >> 8) & 0xFF));
}

void write_u32(std::vector<uint8_t>& buf, uint32_t val) {
    for (int i = 0; i < 4; ++i) {
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

} // namespace

const char* to_string(MessageType type) noexcept {
    switch (type) {
        case MessageType::Handshake: return "Handshake";
        case MessageType::HandshakeAck: return "HandshakeAck";
        case MessageType::ManifestRequest: return "ManifestRequest";
        case MessageType::ManifestResponse: return "ManifestResponse";
        case MessageType::HaveQuery: return "HaveQuery";
        case MessageType::HaveResponse: return "HaveResponse";
        case MessageType::WantChunks: return "WantChunks";
        case MessageType::ChunkData: return "ChunkData";
        case MessageType::Complete: return "Complete";
        case MessageType::Error: return "Error";
        default: return "Unknown";
    }
}

uint32_t crc32(std::span<const uint8_t> data) {
    const auto& table = get_crc32_table();
    uint32_t c = 0xFFFFFFFF;
    for (uint8_t b : data) {
        c = table[(c ^ b) & 0xFF] ^ (c >> 8);
    }
    return c ^ 0xFFFFFFFF;
}

std::vector<uint8_t> WireFraming::encode(MessageType type, std::span<const uint8_t> payload) {
    std::vector<uint8_t> frame;
    frame.reserve(kHeaderSize + payload.size() + kTrailerSize);

    write_u32(frame, kMagic);
    frame.push_back(static_cast<uint8_t>(type));
    write_u32(frame, static_cast<uint32_t>(payload.size()));

    if (!payload.empty()) {
        frame.insert(frame.end(), payload.begin(), payload.end());
    }

    // CRC covers type, length, and payload (from index 4 to end)
    uint32_t check = crc32(std::span<const uint8_t>(frame.data() + 4, 1 + 4 + payload.size()));
    write_u32(frame, check);

    return frame;
}

std::vector<uint8_t> WireFraming::encode(const Frame& frame) {
    return encode(frame.type, frame.payload);
}

void WireFraming::feed(std::span<const uint8_t> bytes) {
    if (!bytes.empty()) {
        buffer_.insert(buffer_.end(), bytes.begin(), bytes.end());
    }
}

void WireFraming::feed(const void* data, size_t size) {
    if (data != nullptr && size > 0) {
        feed(std::span<const uint8_t>(static_cast<const uint8_t*>(data), size));
    }
}

void WireFraming::reset() {
    buffer_.clear();
}

std::optional<Frame> WireFraming::pop_frame() {
    while (buffer_.size() >= kHeaderSize) {
        // Find magic
        uint32_t magic = static_cast<uint32_t>(buffer_[0]) |
                        (static_cast<uint32_t>(buffer_[1]) << 8) |
                        (static_cast<uint32_t>(buffer_[2]) << 16) |
                        (static_cast<uint32_t>(buffer_[3]) << 24);

        if (magic != kMagic) {
            // Drop 1 byte and retry
            buffer_.erase(buffer_.begin());
            continue;
        }

        uint8_t raw_type = buffer_[4];
        if (raw_type < 1 || raw_type > 10) {
            // Invalid message type, drop magic
            buffer_.erase(buffer_.begin(), buffer_.begin() + 4);
            continue;
        }

        uint32_t payload_len = static_cast<uint32_t>(buffer_[5]) |
                              (static_cast<uint32_t>(buffer_[6]) << 8) |
                              (static_cast<uint32_t>(buffer_[7]) << 16) |
                              (static_cast<uint32_t>(buffer_[8]) << 24);

        if (payload_len > kMaxPayload) {
            // Unreasonable payload length, drop magic
            buffer_.erase(buffer_.begin(), buffer_.begin() + 4);
            continue;
        }

        size_t total_frame_len = kHeaderSize + payload_len + kTrailerSize;
        if (buffer_.size() < total_frame_len) {
            // Incomplete frame, wait for more data
            return std::nullopt;
        }

        // Verify CRC
        size_t trailer_offset = kHeaderSize + payload_len;
        uint32_t expected_crc = static_cast<uint32_t>(buffer_[trailer_offset]) |
                               (static_cast<uint32_t>(buffer_[trailer_offset + 1]) << 8) |
                               (static_cast<uint32_t>(buffer_[trailer_offset + 2]) << 16) |
                               (static_cast<uint32_t>(buffer_[trailer_offset + 3]) << 24);

        uint32_t computed_crc = crc32(std::span<const uint8_t>(buffer_.data() + 4, 1 + 4 + payload_len));
        if (computed_crc != expected_crc) {
            // CRC error, drop magic and resync
            buffer_.erase(buffer_.begin(), buffer_.begin() + 4);
            continue;
        }

        Frame f;
        f.type = static_cast<MessageType>(raw_type);
        if (payload_len > 0) {
            f.payload.assign(buffer_.begin() + kHeaderSize, buffer_.begin() + trailer_offset);
        }

        buffer_.erase(buffer_.begin(), buffer_.begin() + total_frame_len);
        return f;
    }

    return std::nullopt;
}

// HandshakeMsg
std::vector<uint8_t> HandshakeMsg::serialize() const {
    std::vector<uint8_t> buf;
    write_u16(buf, version);
    write_u32(buf, capabilities);
    uint16_t id_len = static_cast<uint16_t>(std::min(client_id.size(), static_cast<size_t>(0xFFFF)));
    write_u16(buf, id_len);
    buf.insert(buf.end(), client_id.data(), client_id.data() + id_len);
    return buf;
}

std::optional<HandshakeMsg> HandshakeMsg::deserialize(std::span<const uint8_t> payload) {
    if (payload.size() < 8) return std::nullopt;
    std::span<const uint8_t> cursor = payload;
    HandshakeMsg msg;
    if (!read_u16(cursor, msg.version)) return std::nullopt;
    if (!read_u32(cursor, msg.capabilities)) return std::nullopt;
    uint16_t id_len = 0;
    if (!read_u16(cursor, id_len) || cursor.size() < id_len) return std::nullopt;
    msg.client_id.assign(reinterpret_cast<const char*>(cursor.data()), id_len);
    return msg;
}

// HandshakeAckMsg
std::vector<uint8_t> HandshakeAckMsg::serialize() const {
    std::vector<uint8_t> buf;
    write_u16(buf, version);
    write_u32(buf, capabilities);
    return buf;
}

std::optional<HandshakeAckMsg> HandshakeAckMsg::deserialize(std::span<const uint8_t> payload) {
    if (payload.size() < 6) return std::nullopt;
    std::span<const uint8_t> cursor = payload;
    HandshakeAckMsg msg;
    if (!read_u16(cursor, msg.version)) return std::nullopt;
    if (!read_u32(cursor, msg.capabilities)) return std::nullopt;
    return msg;
}

// ManifestRequestMsg
std::vector<uint8_t> ManifestRequestMsg::serialize() const {
    std::vector<uint8_t> buf(Hash256::kSize);
    std::memcpy(buf.data(), root_hash.data(), Hash256::kSize);
    return buf;
}

std::optional<ManifestRequestMsg> ManifestRequestMsg::deserialize(std::span<const uint8_t> payload) {
    if (payload.size() < Hash256::kSize) return std::nullopt;
    ManifestRequestMsg msg;
    msg.root_hash = Hash256(payload.data());
    return msg;
}

// ManifestResponseMsg
std::vector<uint8_t> ManifestResponseMsg::serialize() const {
    std::vector<uint8_t> buf;
    buf.reserve(Hash256::kSize + 1 + data.size());
    buf.insert(buf.end(), root_hash.data(), root_hash.data() + Hash256::kSize);
    buf.push_back(found ? 1 : 0);
    if (!data.empty()) {
        buf.insert(buf.end(), data.begin(), data.end());
    }
    return buf;
}

std::optional<ManifestResponseMsg> ManifestResponseMsg::deserialize(std::span<const uint8_t> payload) {
    if (payload.size() < Hash256::kSize + 1) return std::nullopt;
    ManifestResponseMsg msg;
    msg.root_hash = Hash256(payload.data());
    msg.found = (payload[Hash256::kSize] != 0);
    if (payload.size() > Hash256::kSize + 1) {
        msg.data.assign(payload.begin() + Hash256::kSize + 1, payload.end());
    }
    return msg;
}

// HaveQueryMsg
std::vector<uint8_t> HaveQueryMsg::serialize() const {
    std::vector<uint8_t> buf;
    write_u32(buf, static_cast<uint32_t>(hashes.size()));
    for (const auto& h : hashes) {
        buf.insert(buf.end(), h.data(), h.data() + Hash256::kSize);
    }
    return buf;
}

std::optional<HaveQueryMsg> HaveQueryMsg::deserialize(std::span<const uint8_t> payload) {
    if (payload.size() < 4) return std::nullopt;
    std::span<const uint8_t> cursor = payload;
    uint32_t count = 0;
    if (!read_u32(cursor, count)) return std::nullopt;
    if (cursor.size() < static_cast<size_t>(count) * Hash256::kSize) return std::nullopt;

    HaveQueryMsg msg;
    msg.hashes.reserve(count);
    for (uint32_t i = 0; i < count; ++i) {
        msg.hashes.emplace_back(cursor.data());
        cursor = cursor.subspan(Hash256::kSize);
    }
    return msg;
}

// HaveResponseMsg
std::vector<uint8_t> HaveResponseMsg::serialize() const {
    std::vector<uint8_t> buf;
    write_u32(buf, static_cast<uint32_t>(have_flags.size()));
    buf.insert(buf.end(), have_flags.begin(), have_flags.end());
    return buf;
}

std::optional<HaveResponseMsg> HaveResponseMsg::deserialize(std::span<const uint8_t> payload) {
    if (payload.size() < 4) return std::nullopt;
    std::span<const uint8_t> cursor = payload;
    uint32_t count = 0;
    if (!read_u32(cursor, count)) return std::nullopt;
    if (cursor.size() < count) return std::nullopt;

    HaveResponseMsg msg;
    msg.have_flags.assign(cursor.begin(), cursor.begin() + count);
    return msg;
}

// WantChunksMsg
std::vector<uint8_t> WantChunksMsg::serialize() const {
    std::vector<uint8_t> buf;
    write_u32(buf, static_cast<uint32_t>(hashes.size()));
    for (const auto& h : hashes) {
        buf.insert(buf.end(), h.data(), h.data() + Hash256::kSize);
    }
    return buf;
}

std::optional<WantChunksMsg> WantChunksMsg::deserialize(std::span<const uint8_t> payload) {
    if (payload.size() < 4) return std::nullopt;
    std::span<const uint8_t> cursor = payload;
    uint32_t count = 0;
    if (!read_u32(cursor, count)) return std::nullopt;
    if (cursor.size() < static_cast<size_t>(count) * Hash256::kSize) return std::nullopt;

    WantChunksMsg msg;
    msg.hashes.reserve(count);
    for (uint32_t i = 0; i < count; ++i) {
        msg.hashes.emplace_back(cursor.data());
        cursor = cursor.subspan(Hash256::kSize);
    }
    return msg;
}

// ChunkDataMsg
std::vector<uint8_t> ChunkDataMsg::serialize() const {
    std::vector<uint8_t> buf;
    buf.reserve(Hash256::kSize + 4 + data.size());
    buf.insert(buf.end(), hash.data(), hash.data() + Hash256::kSize);
    write_u32(buf, static_cast<uint32_t>(data.size()));
    if (!data.empty()) {
        buf.insert(buf.end(), data.begin(), data.end());
    }
    return buf;
}

std::optional<ChunkDataMsg> ChunkDataMsg::deserialize(std::span<const uint8_t> payload) {
    if (payload.size() < Hash256::kSize + 4) return std::nullopt;
    std::span<const uint8_t> cursor = payload;
    ChunkDataMsg msg;
    msg.hash = Hash256(cursor.data());
    cursor = cursor.subspan(Hash256::kSize);

    uint32_t data_len = 0;
    if (!read_u32(cursor, data_len) || cursor.size() < data_len) return std::nullopt;
    if (data_len > 0) {
        msg.data.assign(cursor.begin(), cursor.begin() + data_len);
    }
    return msg;
}

// CompleteMsg
std::vector<uint8_t> CompleteMsg::serialize() const {
    std::vector<uint8_t> buf;
    write_u32(buf, status);
    uint16_t msg_len = static_cast<uint16_t>(std::min(message.size(), static_cast<size_t>(0xFFFF)));
    write_u16(buf, msg_len);
    buf.insert(buf.end(), message.data(), message.data() + msg_len);
    return buf;
}

std::optional<CompleteMsg> CompleteMsg::deserialize(std::span<const uint8_t> payload) {
    if (payload.size() < 6) return std::nullopt;
    std::span<const uint8_t> cursor = payload;
    CompleteMsg msg;
    if (!read_u32(cursor, msg.status)) return std::nullopt;
    uint16_t msg_len = 0;
    if (!read_u16(cursor, msg_len) || cursor.size() < msg_len) return std::nullopt;
    msg.message.assign(reinterpret_cast<const char*>(cursor.data()), msg_len);
    return msg;
}

// ErrorMsg
std::vector<uint8_t> ErrorMsg::serialize() const {
    std::vector<uint8_t> buf;
    write_u32(buf, code);
    uint16_t msg_len = static_cast<uint16_t>(std::min(message.size(), static_cast<size_t>(0xFFFF)));
    write_u16(buf, msg_len);
    buf.insert(buf.end(), message.data(), message.data() + msg_len);
    return buf;
}

std::optional<ErrorMsg> ErrorMsg::deserialize(std::span<const uint8_t> payload) {
    if (payload.size() < 6) return std::nullopt;
    std::span<const uint8_t> cursor = payload;
    ErrorMsg msg;
    if (!read_u32(cursor, msg.code)) return std::nullopt;
    uint16_t msg_len = 0;
    if (!read_u16(cursor, msg_len) || cursor.size() < msg_len) return std::nullopt;
    msg.message.assign(reinterpret_cast<const char*>(cursor.data()), msg_len);
    return msg;
}

} // namespace bro::cas
