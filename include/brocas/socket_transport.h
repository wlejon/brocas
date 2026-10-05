#pragma once

#include <brocas/protocol.h>
#include <brocas/sync.h>

#include <cstdint>
#include <memory>
#include <optional>
#include <string_view>

namespace bro::cas {

class SocketTransport : public ITransport {
public:
    class Server {
    public:
        Server() = default;
        ~Server();

        Server(const Server&) = delete;
        Server& operator=(const Server&) = delete;
        Server(Server&& other) noexcept;
        Server& operator=(Server&& other) noexcept;

        // Bind to localhost on port (0 for ephemeral OS-chosen port)
        static std::unique_ptr<Server> listen(uint16_t port = 0);

        uint16_t port() const noexcept { return port_; }
        std::unique_ptr<SocketTransport> accept_client(int timeout_ms = 10000);
        void close();

    private:
        intptr_t listen_fd_ = -1;
        uint16_t port_ = 0;
    };

    SocketTransport();
    explicit SocketTransport(intptr_t socket_fd);
    ~SocketTransport() override;

    SocketTransport(const SocketTransport&) = delete;
    SocketTransport& operator=(const SocketTransport&) = delete;
    SocketTransport(SocketTransport&& other) noexcept;
    SocketTransport& operator=(SocketTransport&& other) noexcept;

    // Connect to host:port
    static std::unique_ptr<SocketTransport> connect(std::string_view host, uint16_t port, int timeout_ms = 10000);

    bool send_frame(const Frame& frame) override;
    std::optional<Frame> recv_frame() override;
    void close() override;
    bool is_connected() const override;

    intptr_t native_handle() const noexcept { return socket_fd_; }

private:
    intptr_t socket_fd_ = -1;
    WireFraming wire_parser_;
    bool closed_ = false;
};

} // namespace bro::cas
