#include <brocas/socket_transport.h>

#include <chrono>
#include <cstring>
#include <mutex>
#include <thread>
#include <vector>

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
using socket_t = SOCKET;
constexpr socket_t kInvalidSocket = INVALID_SOCKET;
#else
#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
using socket_t = int;
constexpr socket_t kInvalidSocket = -1;
#endif

namespace bro::cas {

namespace {

void ensure_network_init() {
#if defined(_WIN32)
    static std::once_flag flag;
    std::call_once(flag, [] {
        WSADATA wsa;
        WSAStartup(MAKEWORD(2, 2), &wsa);
    });
#endif
}

void close_socket_handle(socket_t s) {
    if (s != kInvalidSocket) {
#if defined(_WIN32)
        closesocket(s);
#else
        ::close(s);
#endif
    }
}

void set_tcp_nodelay(socket_t s) {
    int flag = 1;
    setsockopt(s, IPPROTO_TCP, TCP_NODELAY, reinterpret_cast<const char*>(&flag), sizeof(flag));
}

} // namespace

// --- Server Implementation ---

SocketTransport::Server::~Server() {
    close();
}

SocketTransport::Server::Server(Server&& other) noexcept
    : listen_fd_(other.listen_fd_), port_(other.port_) {
    other.listen_fd_ = -1;
    other.port_ = 0;
}

SocketTransport::Server& SocketTransport::Server::operator=(Server&& other) noexcept {
    if (this != &other) {
        close();
        listen_fd_ = other.listen_fd_;
        port_ = other.port_;
        other.listen_fd_ = -1;
        other.port_ = 0;
    }
    return *this;
}

std::unique_ptr<SocketTransport::Server> SocketTransport::Server::listen(uint16_t port) {
    ensure_network_init();

    socket_t fd = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (fd == kInvalidSocket) {
        return nullptr;
    }

    int reuse = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&reuse), sizeof(reuse));

    sockaddr_in sin{};
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sin.sin_port = htons(port);

    if (::bind(fd, reinterpret_cast<sockaddr*>(&sin), sizeof(sin)) != 0) {
        close_socket_handle(fd);
        return nullptr;
    }

    if (::listen(fd, 5) != 0) {
        close_socket_handle(fd);
        return nullptr;
    }

    // Resolve port if 0 was requested
    socklen_t addrlen = sizeof(sin);
    if (::getsockname(fd, reinterpret_cast<sockaddr*>(&sin), &addrlen) != 0) {
        close_socket_handle(fd);
        return nullptr;
    }

    auto srv = std::unique_ptr<Server>(new Server());
    srv->listen_fd_ = static_cast<intptr_t>(fd);
    srv->port_ = ntohs(sin.sin_port);
    return srv;
}

std::unique_ptr<SocketTransport> SocketTransport::Server::accept_client(int timeout_ms) {
    if (listen_fd_ == -1) return nullptr;

    socket_t lfd = static_cast<socket_t>(listen_fd_);

    fd_set rfds;
    FD_ZERO(&rfds);
    FD_SET(lfd, &rfds);

    timeval tv{};
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;

    int r = ::select(static_cast<int>(lfd + 1), &rfds, nullptr, nullptr, (timeout_ms >= 0) ? &tv : nullptr);
    if (r <= 0) {
        return nullptr;
    }

    sockaddr_in client_addr{};
    socklen_t addrlen = sizeof(client_addr);
    socket_t client_fd = ::accept(lfd, reinterpret_cast<sockaddr*>(&client_addr), &addrlen);
    if (client_fd == kInvalidSocket) {
        return nullptr;
    }

    set_tcp_nodelay(client_fd);
    return std::make_unique<SocketTransport>(static_cast<intptr_t>(client_fd));
}

void SocketTransport::Server::close() {
    if (listen_fd_ != -1) {
        close_socket_handle(static_cast<socket_t>(listen_fd_));
        listen_fd_ = -1;
        port_ = 0;
    }
}

// --- SocketTransport Implementation ---

SocketTransport::SocketTransport() : socket_fd_(-1), closed_(true) {}

SocketTransport::SocketTransport(intptr_t socket_fd)
    : socket_fd_(socket_fd), closed_(socket_fd == -1) {}

SocketTransport::~SocketTransport() {
    close();
}

SocketTransport::SocketTransport(SocketTransport&& other) noexcept
    : socket_fd_(other.socket_fd_), wire_parser_(std::move(other.wire_parser_)), closed_(other.closed_) {
    other.socket_fd_ = -1;
    other.closed_ = true;
}

SocketTransport& SocketTransport::operator=(SocketTransport&& other) noexcept {
    if (this != &other) {
        close();
        socket_fd_ = other.socket_fd_;
        wire_parser_ = std::move(other.wire_parser_);
        closed_ = other.closed_;
        other.socket_fd_ = -1;
        other.closed_ = true;
    }
    return *this;
}

std::unique_ptr<SocketTransport> SocketTransport::connect(std::string_view host, uint16_t port, int timeout_ms) {
    (void)timeout_ms;
    ensure_network_init();

    socket_t fd = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (fd == kInvalidSocket) {
        return nullptr;
    }

    set_tcp_nodelay(fd);

    sockaddr_in sin{};
    sin.sin_family = AF_INET;
    sin.sin_port = htons(port);

    std::string host_str(host);
    if (::inet_pton(AF_INET, host_str.c_str(), &sin.sin_addr) <= 0) {
        close_socket_handle(fd);
        return nullptr;
    }

    auto start_time = std::chrono::steady_clock::now();
    while (true) {
        if (::connect(fd, reinterpret_cast<sockaddr*>(&sin), sizeof(sin)) == 0) {
            return std::make_unique<SocketTransport>(static_cast<intptr_t>(fd));
        }

#if defined(_WIN32)
        int err = WSAGetLastError();
        bool retryable = (err == WSAECONNREFUSED || err == WSAETIMEDOUT || err == WSAEWOULDBLOCK);
#else
        int err = errno;
        bool retryable = (err == ECONNREFUSED || err == ETIMEDOUT || err == EAGAIN || err == EINPROGRESS);
#endif
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start_time).count();
        if (!retryable || elapsed >= timeout_ms) {
            close_socket_handle(fd);
            return nullptr;
        }

        close_socket_handle(fd);
        std::this_thread::sleep_for(std::chrono::milliseconds(20));

        fd = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (fd == kInvalidSocket) {
            return nullptr;
        }
        set_tcp_nodelay(fd);
    }
}

bool SocketTransport::send_frame(const Frame& frame) {
    if (closed_ || socket_fd_ == -1) return false;

    std::vector<uint8_t> encoded = WireFraming::encode(frame);
    size_t total_sent = 0;
    socket_t fd = static_cast<socket_t>(socket_fd_);

    while (total_sent < encoded.size()) {
        const char* p = reinterpret_cast<const char*>(encoded.data() + total_sent);
        int chunk = static_cast<int>(std::min<size_t>(encoded.size() - total_sent, 65536));
        int n = ::send(fd, p, chunk, 0);
        if (n <= 0) {
            close();
            return false;
        }
        total_sent += static_cast<size_t>(n);
    }
    return true;
}

std::optional<Frame> SocketTransport::recv_frame() {
    if (closed_ || socket_fd_ == -1) return std::nullopt;

    // Check if we already buffered a complete frame
    auto f = wire_parser_.pop_frame();
    if (f) return f;

    socket_t fd = static_cast<socket_t>(socket_fd_);
    uint8_t buffer[16384];

    while (!closed_) {
        // Poll for read with 10s timeout
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(fd, &rfds);

        timeval tv{};
        tv.tv_sec = 10;
        tv.tv_usec = 0;

        int r = ::select(static_cast<int>(fd + 1), &rfds, nullptr, nullptr, &tv);
        if (r <= 0) {
            close();
            return std::nullopt;
        }

        int n = ::recv(fd, reinterpret_cast<char*>(buffer), sizeof(buffer), 0);
        if (n <= 0) {
            close();
            return std::nullopt;
        }

        wire_parser_.feed(buffer, static_cast<size_t>(n));
        f = wire_parser_.pop_frame();
        if (f) return f;
    }

    return std::nullopt;
}

void SocketTransport::close() {
    if (!closed_ && socket_fd_ != -1) {
        close_socket_handle(static_cast<socket_t>(socket_fd_));
        socket_fd_ = -1;
        closed_ = true;
    }
}

bool SocketTransport::is_connected() const {
    return !closed_ && socket_fd_ != -1;
}

} // namespace bro::cas
