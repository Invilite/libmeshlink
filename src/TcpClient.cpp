#include "transport/TcpClient.h"
#include "transport/platform.h"

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <netdb.h>
#include <netinet/in.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>

namespace invilite::Transport {

std::string_view connectErrorName(ConnectError error) {
    switch (error) {
        case ConnectError::None:             return "none";
        case ConnectError::AlreadyConnected: return "already connected";
        case ConnectError::ResolveFailed:    return "address resolution failed";
        case ConnectError::SocketCreation:   return "socket creation failed";
        case ConnectError::NonBlocking:      return "non-blocking mode failed";
        case ConnectError::PortReuse:        return "local port reuse option failed";
        case ConnectError::BindFailed:       return "local port bind failed";
        case ConnectError::KeepAlive:        return "keepalive option failed";
        case ConnectError::ConnectFailed:    return "connect failed";
        case ConnectError::PollFailed:       return "poll failed";
        case ConnectError::TimedOut:         return "timed out";
        case ConnectError::Refused:          return "refused or unreachable";
    }
    return "unknown";
}

namespace {

// One TCP connect attempt — the code shared by connect() and connectSimultaneous(): a socket that allows local port
// reuse, optionally bound to `localEndpoint`, a non-blocking connect and a wait of at most `timeout`. On success
// `connectedSocket` holds the socket; on failure it is closed and -1.
ConnectError connectOnce(const sockaddr* remote, socklen_t remoteLength, const sockaddr* localEndpoint, socklen_t localLength, std::chrono::milliseconds timeout, int& connectedSocket) {
    connectedSocket = -1;
    const int sock = ::socket(remote->sa_family, SOCK_STREAM, IPPROTO_TCP);
    if (sock < 0) return ConnectError::SocketCreation;

    const auto fail = [sock](ConnectError error) { ::close(sock); return error; };

    // Every outgoing socket allows reuse of its local port from the start: which connection will later carry a NAT
    // hole punch (F7) is not known in advance, and the kernel lets a second socket bind only if all of them opted in
    if (!Platform::allowLocalPortReuse(sock)) return fail(ConnectError::PortReuse);
    if (localEndpoint != nullptr && ::bind(sock, localEndpoint, localLength) < 0) return fail(ConnectError::BindFailed);

    // Non-blocking for timeout-based connect
    if (!Platform::setNonBlocking(sock)) return fail(ConnectError::NonBlocking);

    const int result = ::connect(sock, remote, remoteLength);
    if (result < 0 && errno != EINPROGRESS) return fail(ConnectError::ConnectFailed);

    if (result != 0) {
        // EINPROGRESS — wait for socket to become writable within timeout (poll: no FD_SETSIZE limit, unlike select)
        pollfd pending{ sock, POLLOUT, 0 };
        int pollResult;
        do {
            pollResult = Platform::waitForSockets(&pending, 1, static_cast<int>(timeout.count()));
        } while (pollResult < 0 && errno == EINTR);

        if (pollResult < 0) return fail(ConnectError::PollFailed);
        if (pollResult == 0) return fail(ConnectError::TimedOut);

        // Check connect result via SO_ERROR
        int       soError = 0;
        socklen_t errLen  = sizeof(soError);
        if (::getsockopt(sock, SOL_SOCKET, SO_ERROR, &soError, &errLen) < 0 || soError != 0) return fail(ConnectError::Refused);
    }
    // result == 0: instant connect (rare — e.g. loopback with nothing to wait for)

    connectedSocket = sock;
    return ConnectError::None;
}

} // namespace

TcpClient::TcpClient() : clientSocket(-1) {}

TcpClient::~TcpClient() {
    this->disconnect();
}

ConnectError TcpClient::connect(const std::string& address, int port, std::chrono::seconds timeout) {
    if (this->clientSocket != -1) {
        return ConnectError::AlreadyConnected;
    }

    // Resolve address — handles IPv4 literals, IPv6 literals, and hostnames
    addrinfo hints{};
    hints.ai_family   = AF_UNSPEC;                                                  // accept both IPv4 and IPv6
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    char portStr[8];
    std::snprintf(portStr, sizeof(portStr), "%d", port);

    addrinfo* resolved = nullptr;
    const int gai = ::getaddrinfo(address.c_str(), portStr, &hints, &resolved);
    if (gai != 0) {
        return ConnectError::ResolveFailed;
    }

    sockaddr_storage remoteAddress{};
    ConnectError     lastError = ConnectError::ConnectFailed;
    int              sock      = -1;

    // Try each resolved address in turn — first one that connects wins
    for (addrinfo* rp = resolved; rp != nullptr; rp = rp->ai_next) {
        lastError = connectOnce(rp->ai_addr, rp->ai_addrlen, nullptr, 0, timeout, sock);
        if (lastError == ConnectError::None) {
            std::memcpy(&remoteAddress, rp->ai_addr, rp->ai_addrlen);
            break;
        }
    }

    ::freeaddrinfo(resolved);

    if (sock < 0) {
        return lastError;
    }
    return this->adoptConnectedSocket(sock, remoteAddress);
}

ConnectError TcpClient::connectSimultaneous(const uint16_t localPort, const std::string& remoteAddress, const int remotePort, const std::chrono::milliseconds timeout) {
    if (this->clientSocket != -1) {
        return ConnectError::AlreadyConnected;
    }

    // Numeric only: the address comes from what a neighbor observed, never from a name lookup
    addrinfo hints{};
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_flags    = AI_NUMERICHOST | AI_NUMERICSERV;

    char portStr[8];
    std::snprintf(portStr, sizeof(portStr), "%d", remotePort);

    addrinfo* resolved = nullptr;
    if (::getaddrinfo(remoteAddress.c_str(), portStr, &hints, &resolved) != 0) {
        return ConnectError::ResolveFailed;
    }

    sockaddr_storage remote{};
    const socklen_t  remoteLength = resolved->ai_addrlen;
    std::memcpy(&remote, resolved->ai_addr, remoteLength);
    ::freeaddrinfo(resolved);

    // Wildcard address of the same family on the given port: the kernel picks the source address by route, the same
    // one the existing connection on this port uses
    sockaddr_storage local{};
    socklen_t        localLength;
    if (remote.ss_family == AF_INET6) {
        auto* local6 = reinterpret_cast<sockaddr_in6*>(&local);
        local6->sin6_family = AF_INET6;
        local6->sin6_addr   = in6addr_any;
        local6->sin6_port   = htons(localPort);
        localLength         = sizeof(sockaddr_in6);
    } else {
        auto* local4 = reinterpret_cast<sockaddr_in*>(&local);
        local4->sin_family      = AF_INET;
        local4->sin_addr.s_addr = htonl(INADDR_ANY);
        local4->sin_port        = htons(localPort);
        localLength             = sizeof(sockaddr_in);
    }

    int sock = -1;
    const ConnectError error = connectOnce(reinterpret_cast<const sockaddr*>(&remote), remoteLength, reinterpret_cast<const sockaddr*>(&local), localLength, timeout, sock);
    if (error != ConnectError::None) {
        return error;
    }
    return this->adoptConnectedSocket(sock, remote);
}

ConnectError TcpClient::adoptConnectedSocket(const int connectedSocket, const sockaddr_storage& remoteAddress) {
    this->clientSocket = connectedSocket;

    // Enable TCP keepalive
    const int enable = 1;
    if (::setsockopt(this->clientSocket, SOL_SOCKET, SO_KEEPALIVE, &enable, sizeof(enable)) < 0) {
        this->disconnect();
        return ConnectError::KeepAlive;
    }

    // Fire callback — caller may extract socket via release() if they want ownership. An exception from it reaches the
    // caller of connect(), which knows how to report it; the socket stays owned (and is closed) by this client.
    if (this->onConnect_) this->onConnect_(this->clientSocket, &remoteAddress);

    return ConnectError::None;
}

void TcpClient::disconnect() {
    if (this->clientSocket != -1) {
        ::shutdown(this->clientSocket, SHUT_RDWR);
        ::close(this->clientSocket);
        this->clientSocket = -1;
    }
}

int TcpClient::release() {
    const int fd = this->clientSocket;
    this->clientSocket = -1;
    return fd;
}

void TcpClient::onConnect(std::function<void(int, const sockaddr_storage*)> cb) {
    this->onConnect_ = std::move(cb);
}

} // namespace invilite::Transport