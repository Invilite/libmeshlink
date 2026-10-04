#include "transport/TcpClient.h"
#include "transport/platform.h"

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <netdb.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <iostream>

namespace invilite::Transport {

TcpClient::TcpClient() : clientSocket(-1) {}

TcpClient::~TcpClient() {
    this->disconnect();
}

uint8_t TcpClient::connect(const std::string& address, int port, std::chrono::seconds timeout) {
    if (this->clientSocket != -1) {
        return 1;                                                                   // already connected
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
        std::cerr << "TcpClient: getaddrinfo('" << address << "') failed: " << ::gai_strerror(gai) << std::endl;
        return 2;
    }

    sockaddr_storage remoteAddress{};
    uint8_t          lastError = 100;
    int              sock      = -1;

    // Try each resolved address in turn — first one that connects wins
    for (addrinfo* rp = resolved; rp != nullptr; rp = rp->ai_next) {
        sock = ::socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (sock < 0) {
            lastError = 3;
            continue;
        }

        // Non-blocking for timeout-based connect
        if (!Platform::setNonBlocking(sock)) {
            ::close(sock);
            sock = -1;
            lastError = 11;
            continue;
        }

        const int result = ::connect(sock, rp->ai_addr, rp->ai_addrlen);

        if (result == 0) {
            // Instant connect (rare — e.g. loopback with nothing to wait for)
            std::memcpy(&remoteAddress, rp->ai_addr, rp->ai_addrlen);
            break;
        }

        if (result < 0 && errno != EINPROGRESS) {
            ::close(sock);
            sock = -1;
            lastError = 100;
            continue;
        }

        // EINPROGRESS — wait for socket to become writable within timeout (poll: no FD_SETSIZE limit, unlike select)
        pollfd pending{ sock, POLLOUT, 0 };
        int pollResult;
        do {
            pollResult = Platform::waitForSockets(&pending, 1, static_cast<int>(std::chrono::duration_cast<std::chrono::milliseconds>(timeout).count()));
        } while (pollResult < 0 && errno == EINTR);

        if (pollResult < 0) {
            ::close(sock);
            sock = -1;
            lastError = 101;
            continue;
        }

        if (pollResult == 0) {
            ::close(sock);
            sock = -1;
            lastError = 102;
            continue;
        }

        // Check connect result via SO_ERROR
        int       soError = 0;
        socklen_t errLen  = sizeof(soError);
        if (::getsockopt(sock, SOL_SOCKET, SO_ERROR, &soError, &errLen) < 0 || soError != 0) {
            ::close(sock);
            sock = -1;
            lastError = 103;
            continue;
        }

        // Success
        std::memcpy(&remoteAddress, rp->ai_addr, rp->ai_addrlen);
        break;
    }

    ::freeaddrinfo(resolved);

    if (sock < 0) {
        return lastError;
    }

    this->clientSocket = sock;

    // Enable TCP keepalive
    const int enable = 1;
    if (::setsockopt(this->clientSocket, SOL_SOCKET, SO_KEEPALIVE, &enable, sizeof(enable)) < 0) {
        this->disconnect();
        return 14;
    }

    // Fire callback — caller may extract socket via release() if they want ownership
    try {
        if (this->onConnect_) {
            this->onConnect_(this->clientSocket, &remoteAddress);
        }
    } catch (const std::exception& e) {
        std::cerr << "TcpClient: exception in onConnect callback: " << e.what() << std::endl;
    } catch (...) {
        std::cerr << "TcpClient: unknown exception in onConnect callback" << std::endl;
    }

    return 0;
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