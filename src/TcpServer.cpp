#include "transport/TcpServer.h"

#include <cerrno>
#include <chrono>

std::string_view invilite::Transport::listenErrorName(ListenError error) {
    switch (error) {
        case ListenError::None:           return "none";
        case ListenError::InvalidAddress: return "listen address is not a numeric IPv4/IPv6 address";
        case ListenError::SocketCreation: return "socket creation";
        case ListenError::SocketOption:   return "socket option";
        case ListenError::Bind:           return "bind";
        case ListenError::Listen:         return "listen";
        case ListenError::NonBlocking:    return "non-blocking mode";
        case ListenError::WakeupSignal:   return "wakeup signal";
    }
    return "unknown";
}

invilite::Transport::TcpServer::TcpServer(std::string listenAddress, const int port, const int backlog)
    : listenAddress(std::move(listenAddress)), serverPort(port), backlog(backlog), serverSocket(-1) {}

invilite::Transport::TcpServer::~TcpServer() {
    this->stop();                                                                   // a still-running listener thread would std::terminate on destruction
}

invilite::Transport::ListenStartResult invilite::Transport::TcpServer::start() {
    // Stop server if running
    this->stop();

    // Resolve the bind address first: the socket family follows from it
    sockaddr_storage bindAddress{};
    socklen_t        bindAddressLength = 0;
    bool             bindsEveryIpv6Interface = false;
    if (auto* v6 = reinterpret_cast<sockaddr_in6*>(&bindAddress); inet_pton(AF_INET6, this->listenAddress.c_str(), &v6->sin6_addr) == 1) {
        v6->sin6_family = AF_INET6;
        v6->sin6_port   = htons(this->serverPort);
        bindAddressLength = sizeof(sockaddr_in6);
        bindsEveryIpv6Interface = IN6_IS_ADDR_UNSPECIFIED(&v6->sin6_addr);
    } else if (auto* v4 = reinterpret_cast<sockaddr_in*>(&bindAddress); inet_pton(AF_INET, this->listenAddress.c_str(), &v4->sin_addr) == 1) {
        v4->sin_family = AF_INET;
        v4->sin_port   = htons(this->serverPort);
        bindAddressLength = sizeof(sockaddr_in);
    } else {
        return {ListenError::InvalidAddress, 0};
    }

    // Create new server socket
    this->serverSocket = socket(bindAddress.ss_family, SOCK_STREAM, 0);
    if (this->serverSocket == -1) {
        return {ListenError::SocketCreation, errno};
    }

    int opt;

    struct timeval sendTimeout;
    sendTimeout.tv_sec = 5;  // 5 seconds
    sendTimeout.tv_usec = 0; // 0 microseconds

    // Set reuse address option
    opt = 1;
    if (setsockopt(this->serverSocket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) == -1) {
        return {ListenError::SocketOption, errno};
    }

    // Set TCP keep alive option
    opt = 1;
    if (setsockopt(this->serverSocket, SOL_SOCKET, SO_KEEPALIVE, &opt, sizeof(opt)) == -1) {
        return {ListenError::SocketOption, errno};
    }

    // Send max. socket data send time
    if (setsockopt(this->serverSocket, SOL_SOCKET, SO_SNDTIMEO, (const char*)&sendTimeout, sizeof(sendTimeout)) < 0) {
        return {ListenError::SocketOption, errno};
    }

    // "::" also accepts IPv4 (dual stack): the OS default for IPV6_V6ONLY differs between systems, so set it explicitly
    if (bindsEveryIpv6Interface) {
        opt = 0;
        if (setsockopt(this->serverSocket, IPPROTO_IPV6, IPV6_V6ONLY, &opt, sizeof(opt)) < 0) {
            return {ListenError::SocketOption, errno};
        }
    }

    if (bind(this->serverSocket, reinterpret_cast<sockaddr*>(&bindAddress), bindAddressLength) < 0) {
        return {ListenError::Bind, errno};
    }

    if (listen(this->serverSocket, this->backlog) < 0) {
        return {ListenError::Listen, errno};
    }

    // Non-blocking accept: a client that resets between poll() and accept() must not leave the thread stuck in accept()
    if (!Platform::setNonBlocking(this->serverSocket)) {
        return {ListenError::NonBlocking, errno};
    }

    try {
        this->stopSignal.open();
    } catch (const std::exception&) {
        return {ListenError::WakeupSignal, 0};                                      // the exception carries no errno
    }

    // Start server accept thread
    this->stopServer = false;
    this->serverThread = std::thread(&TcpServer::serverListener, this);
    Platform::setThreadName(this->serverThread, "TcpServer");

    return {};
}

void invilite::Transport::TcpServer::stop() {
    // Wake the listener explicitly and wait for it: only then close the socket, so the thread never polls or
    // accepts on a closed (or already reused) descriptor.
    this->stopServer = true;
    this->stopSignal.notify();

    if (this->serverThread.joinable()) {
        this->serverThread.join();
    }

    if (this->serverSocket != -1) {
        close(this->serverSocket);
        this->serverSocket = -1;
    }
    this->stopSignal.close();
}

void invilite::Transport::TcpServer::serverListener() {
    pollfd watched[2] = {
        { this->serverSocket,           POLLIN, 0 },
        { this->stopSignal.readHandle(), POLLIN, 0 },
    };

    while (!this->stopServer) {
        const int ready = Platform::waitForSockets(watched, 2, 500);                // timeout is only a safety net: stop() wakes us
        if (ready < 0) {
            if (errno == EINTR) continue;
            if (this->onListenerFailureCallback) this->onListenerFailureCallback(ListenerFailure::PollFailed, errno);
            break;                                                                  // retrying a failing poll would spin at 100% CPU
        }
        if (ready == 0 || !(watched[0].revents & POLLIN)) continue;

        // Accept everything that is pending: one readiness event may cover several connections
        while (!this->stopServer) {
            sockaddr_storage clientAddress{};
            socklen_t clientAddressLength = sizeof(clientAddress);
            const int clientSocket = accept(this->serverSocket, reinterpret_cast<sockaddr*>(&clientAddress), &clientAddressLength);

            if (clientSocket < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) break;                 // queue drained
                if (errno == EINTR || errno == ECONNABORTED) continue;              // transient, try the next one
                // Out of descriptors (EMFILE/ENFILE) or similar: the connection stays queued and poll() keeps reporting it.
                // Back off briefly instead of spinning; a burst of refused clients is better than a pegged CPU.
                if (this->onListenerFailureCallback) this->onListenerFailureCallback(ListenerFailure::AcceptFailed, errno);
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
                break;
            }

            if (this->on_connect_callback_) {
                this->on_connect_callback_(clientSocket, &clientAddress);
            } else {
                close(clientSocket);                                                // nobody takes ownership: do not leak it
            }
        }
    }
}

void invilite::Transport::TcpServer::onConnect(const OnConnectCallback &callback) {
    on_connect_callback_ = callback;
}

void invilite::Transport::TcpServer::onListenerFailure(const OnListenerFailureCallback& callback) {
    this->onListenerFailureCallback = callback;
}
