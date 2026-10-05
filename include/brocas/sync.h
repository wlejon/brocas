#pragma once

#include <brocas/hash.h>
#include <brocas/manifest.h>
#include <brocas/protocol.h>
#include <brocas/store.h>

#include <condition_variable>
#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>
#include <queue>
#include <string>
#include <vector>

namespace bro::cas {

class ITransport {
public:
    virtual ~ITransport() = default;
    virtual bool send_frame(const Frame& frame) = 0;
    virtual std::optional<Frame> recv_frame() = 0;
    virtual void close() = 0;
    virtual bool is_connected() const = 0;
};

// In-memory bi-directional transport for testing and local IPC
class MemoryTransport : public ITransport {
public:
    MemoryTransport();
    ~MemoryTransport() override;

    // Creates an interconnected pair of endpoints (peer A and peer B)
    static std::pair<std::shared_ptr<MemoryTransport>, std::shared_ptr<MemoryTransport>> create_pair();

    bool send_frame(const Frame& frame) override;
    std::optional<Frame> recv_frame() override;
    void close() override;
    bool is_connected() const override;

    // Simulation controls for testing
    void set_disconnect_after_sends(size_t count);
    void set_disconnect_after_recvs(size_t count);

private:
    struct Channel {
        std::mutex mutex;
        std::condition_variable cv;
        std::queue<Frame> frames;
        bool closed = false;
        size_t send_count = 0;
        size_t recv_count = 0;
        size_t max_sends = static_cast<size_t>(-1);
        size_t max_recvs = static_cast<size_t>(-1);
    };

    std::shared_ptr<Channel> outgoing_;
    std::shared_ptr<Channel> incoming_;
    bool closed_ = false;

    MemoryTransport(std::shared_ptr<Channel> out, std::shared_ptr<Channel> in);
};

struct SyncStats {
    size_t chunks_requested = 0;
    size_t chunks_received = 0;
    uint64_t bytes_transferred = 0;
    size_t manifests_transferred = 0;

    auto operator<=>(const SyncStats& other) const = default;
    bool operator==(const SyncStats& other) const = default;
};

class SyncSender {
public:
    explicit SyncSender(const Store& store);

    // Serves sync requests until transport closes or an error occurs
    bool run(ITransport& transport);

private:
    const Store& store_;
};

class SyncReceiver {
public:
    explicit SyncReceiver(Store& store);

    // Sync a root manifest tree from remote sender into local CAS store.
    // Only transfers missing manifests and missing chunks.
    // If interrupted, returns false; calling again resumes without re-downloading.
    bool sync_manifest(ITransport& transport, const Hash256& root_hash, SyncStats* stats = nullptr);

private:
    Store& store_;

    bool fetch_chunk_or_manifest(ITransport& transport, const Hash256& hash,
                                 std::vector<uint8_t>& out, SyncStats* stats);
};

} // namespace bro::cas
