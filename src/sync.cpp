#include <brocas/sync.h>

#include <queue>
#include <unordered_set>

namespace bro::cas {

MemoryTransport::MemoryTransport(std::shared_ptr<Channel> out, std::shared_ptr<Channel> in)
    : outgoing_(std::move(out)), incoming_(std::move(in)) {}

MemoryTransport::MemoryTransport()
    : outgoing_(std::make_shared<Channel>()), incoming_(std::make_shared<Channel>()) {}

MemoryTransport::~MemoryTransport() {
    close();
}

std::pair<std::shared_ptr<MemoryTransport>, std::shared_ptr<MemoryTransport>> MemoryTransport::create_pair() {
    auto ch1 = std::make_shared<Channel>();
    auto ch2 = std::make_shared<Channel>();

    auto t1 = std::shared_ptr<MemoryTransport>(new MemoryTransport(ch1, ch2));
    auto t2 = std::shared_ptr<MemoryTransport>(new MemoryTransport(ch2, ch1));

    return {t1, t2};
}

void MemoryTransport::set_disconnect_after_sends(size_t count) {
    std::lock_guard<std::mutex> lock(outgoing_->mutex);
    outgoing_->max_sends = count;
}

void MemoryTransport::set_disconnect_after_recvs(size_t count) {
    std::lock_guard<std::mutex> lock(incoming_->mutex);
    incoming_->max_recvs = count;
}

bool MemoryTransport::send_frame(const Frame& frame) {
    std::lock_guard<std::mutex> lock(outgoing_->mutex);
    if (closed_ || outgoing_->closed) {
        return false;
    }

    if (outgoing_->send_count >= outgoing_->max_sends) {
        outgoing_->closed = true;
        outgoing_->cv.notify_all();
        return false;
    }

    outgoing_->frames.push(frame);
    outgoing_->send_count++;
    outgoing_->cv.notify_one();
    return true;
}

std::optional<Frame> MemoryTransport::recv_frame() {
    std::unique_lock<std::mutex> lock(incoming_->mutex);
    incoming_->cv.wait(lock, [&] {
        return closed_ || incoming_->closed || !incoming_->frames.empty();
    });

    if (!incoming_->frames.empty()) {
        if (incoming_->recv_count >= incoming_->max_recvs) {
            incoming_->closed = true;
            return std::nullopt;
        }

        Frame f = std::move(incoming_->frames.front());
        incoming_->frames.pop();
        incoming_->recv_count++;
        return f;
    }

    return std::nullopt;
}

void MemoryTransport::close() {
    closed_ = true;
    if (outgoing_) {
        std::lock_guard<std::mutex> lock(outgoing_->mutex);
        outgoing_->closed = true;
        outgoing_->cv.notify_all();
    }
    if (incoming_) {
        std::lock_guard<std::mutex> lock(incoming_->mutex);
        incoming_->closed = true;
        incoming_->cv.notify_all();
    }
}

bool MemoryTransport::is_connected() const {
    if (closed_) return false;
    if (outgoing_) {
        std::lock_guard<std::mutex> lock(outgoing_->mutex);
        if (outgoing_->closed) return false;
    }
    if (incoming_) {
        std::lock_guard<std::mutex> lock(incoming_->mutex);
        if (incoming_->closed) return false;
    }
    return true;
}

// SyncSender
SyncSender::SyncSender(const Store& store) : store_(store) {}

bool SyncSender::run(ITransport& transport) {
    while (transport.is_connected()) {
        auto frame_opt = transport.recv_frame();
        if (!frame_opt) {
            break;
        }

        const Frame& frame = *frame_opt;
        switch (frame.type) {
            case MessageType::Handshake: {
                auto msg = HandshakeMsg::deserialize(frame.payload);
                if (!msg) {
                    transport.send_frame(Frame{MessageType::Error, ErrorMsg{400, "Bad handshake"}.serialize()});
                    return false;
                }
                HandshakeAckMsg ack{1, 0};
                if (!transport.send_frame(Frame{MessageType::HandshakeAck, ack.serialize()})) {
                    return false;
                }
                break;
            }
            case MessageType::ManifestRequest: {
                auto msg = ManifestRequestMsg::deserialize(frame.payload);
                if (!msg) {
                    transport.send_frame(Frame{MessageType::Error, ErrorMsg{400, "Bad manifest request"}.serialize()});
                    return false;
                }
                ManifestResponseMsg resp;
                resp.root_hash = msg->root_hash;
                auto data = store_.read_chunk(msg->root_hash);
                if (data) {
                    resp.found = true;
                    resp.data = *data;
                } else {
                    resp.found = false;
                }
                if (!transport.send_frame(Frame{MessageType::ManifestResponse, resp.serialize()})) {
                    return false;
                }
                break;
            }
            case MessageType::HaveQuery: {
                auto msg = HaveQueryMsg::deserialize(frame.payload);
                if (!msg) {
                    transport.send_frame(Frame{MessageType::Error, ErrorMsg{400, "Bad have query"}.serialize()});
                    return false;
                }
                HaveResponseMsg resp;
                resp.have_flags.reserve(msg->hashes.size());
                for (const auto& h : msg->hashes) {
                    resp.have_flags.push_back(store_.has_chunk(h) ? 1 : 0);
                }
                if (!transport.send_frame(Frame{MessageType::HaveResponse, resp.serialize()})) {
                    return false;
                }
                break;
            }
            case MessageType::WantChunks: {
                auto msg = WantChunksMsg::deserialize(frame.payload);
                if (!msg) {
                    transport.send_frame(Frame{MessageType::Error, ErrorMsg{400, "Bad want chunks"}.serialize()});
                    return false;
                }
                for (const auto& h : msg->hashes) {
                    auto data = store_.read_chunk(h);
                    if (!data) {
                        transport.send_frame(Frame{MessageType::Error, ErrorMsg{404, "Missing requested chunk"}.serialize()});
                        return false;
                    }
                    ChunkDataMsg chunk_msg;
                    chunk_msg.hash = h;
                    chunk_msg.data = *data;
                    if (!transport.send_frame(Frame{MessageType::ChunkData, chunk_msg.serialize()})) {
                        return false;
                    }
                }
                CompleteMsg comp{0, "Chunks transferred"};
                if (!transport.send_frame(Frame{MessageType::Complete, comp.serialize()})) {
                    return false;
                }
                break;
            }
            case MessageType::Complete: {
                return true;
            }
            case MessageType::Error: {
                return false;
            }
            default:
                break;
        }
    }

    return true;
}

// SyncReceiver
SyncReceiver::SyncReceiver(Store& store) : store_(store) {}

bool SyncReceiver::sync_manifest(ITransport& transport, const Hash256& root_hash, SyncStats* stats) {
    if (root_hash.is_zero()) {
        return false;
    }

    // Step 1: Handshake
    HandshakeMsg hs{1, 0, "brocas-sync"};
    if (!transport.send_frame(Frame{MessageType::Handshake, hs.serialize()})) {
        return false;
    }

    auto hs_ack_frame = transport.recv_frame();
    if (!hs_ack_frame || hs_ack_frame->type != MessageType::HandshakeAck) {
        return false;
    }

    // Step 2: Fetch and traverse all manifest nodes
    std::unordered_set<Hash256> visited_manifests;
    std::queue<Hash256> pending_manifests;

    pending_manifests.push(root_hash);
    visited_manifests.insert(root_hash);

    while (!pending_manifests.empty()) {
        Hash256 curr = pending_manifests.front();
        pending_manifests.pop();

        if (!store_.has_chunk(curr)) {
            ManifestRequestMsg req{curr};
            if (!transport.send_frame(Frame{MessageType::ManifestRequest, req.serialize()})) {
                return false;
            }

            auto resp_frame = transport.recv_frame();
            if (!resp_frame || resp_frame->type != MessageType::ManifestResponse) {
                return false;
            }

            auto resp = ManifestResponseMsg::deserialize(resp_frame->payload);
            if (!resp || !resp->found) {
                return false;
            }

            if (Hasher::hash(resp->data) != curr) {
                return false;
            }

            store_.write_chunk(curr, resp->data);
            if (stats) {
                stats->manifests_transferred++;
                stats->bytes_transferred += resp->data.size();
            }
        }

        auto data = store_.read_chunk(curr);
        if (!data) return false;

        if (auto man = Manifest::deserialize(*data)) {
            for (const auto& entry : man->entries) {
                if (entry.kind == EntryKind::Directory || entry.kind == EntryKind::MultiChunkRegular) {
                    if (!entry.hash.is_zero() && visited_manifests.insert(entry.hash).second) {
                        pending_manifests.push(entry.hash);
                    }
                }
            }
        }
    }

    // Step 3: Collect all referenced chunks and compute missing set
    auto all_hashes = collect_manifest_reachable_hashes(store_, root_hash);
    std::vector<Hash256> missing_chunks;
    for (const auto& h : all_hashes) {
        if (!store_.has_chunk(h)) {
            missing_chunks.push_back(h);
        }
    }

    if (stats) {
        stats->chunks_requested += missing_chunks.size();
    }

    if (missing_chunks.empty()) {
        CompleteMsg comp{0, "Up to date"};
        transport.send_frame(Frame{MessageType::Complete, comp.serialize()});
        return true;
    }

    // Step 4: Request missing chunks
    WantChunksMsg want{missing_chunks};
    if (!transport.send_frame(Frame{MessageType::WantChunks, want.serialize()})) {
        return false;
    }

    // Step 5: Receive chunks until Complete
    while (true) {
        auto chunk_frame = transport.recv_frame();
        if (!chunk_frame) {
            // Transfer interrupted!
            return false;
        }

        if (chunk_frame->type == MessageType::Complete) {
            break;
        }

        if (chunk_frame->type == MessageType::Error) {
            return false;
        }

        if (chunk_frame->type != MessageType::ChunkData) {
            return false;
        }

        auto cmsg = ChunkDataMsg::deserialize(chunk_frame->payload);
        if (!cmsg) {
            return false;
        }

        // Verify hash
        if (Hasher::hash(cmsg->data) != cmsg->hash) {
            return false;
        }

        store_.write_chunk(cmsg->hash, cmsg->data);
        if (stats) {
            stats->chunks_received++;
            stats->bytes_transferred += cmsg->data.size();
        }
    }

    // Step 6: Verify all chunks now present
    for (const auto& h : all_hashes) {
        if (!store_.has_chunk(h)) {
            return false;
        }
    }

    return true;
}

} // namespace bro::cas
