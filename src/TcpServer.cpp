#include "transport/TcpServer.h"

invilite::Transport::TcpServer::TcpServer(std::string listenAddress, const int port, const int backlog)
    : listenAddress(std::move(listenAddress)), serverPort(port), backlog(backlog), serverSocket(-1) {}

invilite::Transport::TcpServer::~TcpServer() {
    if (serverSocket != -1) {
        close(serverSocket);
    }
}

int invilite::Transport::TcpServer::start() {
    // Stop server if running
    this->stop();

    // Resolve the bind address first — the socket family follows from it
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
        std::cerr << "Error: listen address is not a numeric IPv4/IPv6 address: " << this->listenAddress << std::endl;
        return -8;
    }

    // Create new server socket
    this->serverSocket = socket(bindAddress.ss_family, SOCK_STREAM, 0);
    if (this->serverSocket == -1) {
        std::cerr << "Error: Cannot create socket" << std::endl;
        return -1;
    }

    int opt;

    struct timeval sendTimeout;
    sendTimeout.tv_sec = 5;  // 5 seconds
    sendTimeout.tv_usec = 0; // 0 microseconds

    // Set reuse address option
    opt = 1;
    if (setsockopt(this->serverSocket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) == -1) {
        perror("setsockopt");
        return -2;
    }

    // Set TCP keep alive option
    opt = 1;
    if (setsockopt(this->serverSocket, SOL_SOCKET, SO_KEEPALIVE, &opt, sizeof(opt)) == -1) {
        perror("setsockopt");
        return -3;
    }

    // Send max. socket data send time
    if (setsockopt(this->serverSocket, SOL_SOCKET, SO_SNDTIMEO, (const char*)&sendTimeout, sizeof(sendTimeout)) < 0) {
        perror("setsockopt");
        return -4;
    }

    // "::" also accepts IPv4 (dual stack) — the OS default for IPV6_V6ONLY differs between systems, so set it explicitly
    if (bindsEveryIpv6Interface) {
        opt = 0;
        if (setsockopt(this->serverSocket, IPPROTO_IPV6, IPV6_V6ONLY, &opt, sizeof(opt)) < 0) {
            perror("setsockopt");
            return -5;
        }
    }

    if (bind(this->serverSocket, reinterpret_cast<sockaddr*>(&bindAddress), bindAddressLength) < 0) {
        std::cerr << "Error: Cannot bind socket to " << this->listenAddress << ":" << this->serverPort << std::endl;
        return -6;
    }

    if (listen(this->serverSocket, this->backlog) < 0) {
        std::cerr << "Error: Cannot listen on socket" << std::endl;
        return -7;
    }

    // Start server accept thread
    this->stopServer = false;
    this->serverThread = std::thread(&TcpServer::serverListener, this);
    pthread_setname_np(this->serverThread.native_handle(), "TcpServer");

    return 0;
}

void invilite::Transport::TcpServer::stop() {
    // Stop server thread
    this->stopServer = true;

    // Shutdown socket
    if (this->serverSocket != -1) {
        shutdown(this->serverSocket, SHUT_RDWR);
    }

    // Wait for server thread to finish
    if (this->serverThread.joinable()) {
        this->serverThread.join();
    }

    // Close server socket
    close(this->serverSocket);
    this->serverSocket = -1;
}

void invilite::Transport::TcpServer::serverListener() {
    int epoll_fd = epoll_create1(0);
    if (epoll_fd == -1) {
        std::cerr << "Error: Cannot create epoll" << std::endl;
        return;
    }

    const int MAX_EVENTS = 25;
    struct epoll_event ev, events[MAX_EVENTS];
    ev.events = EPOLLIN;
    ev.data.fd = this->serverSocket;

    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, this->serverSocket, &ev) == -1) {
        std::cerr << "Error: Cannot add server socket to epoll" << std::endl;
        close(epoll_fd);
        return;
    }

    while (!this->stopServer) {
        int nfds = epoll_wait(epoll_fd, events, MAX_EVENTS, 500); // Timeout 500 ms
        if (nfds == -1) {
            std::cerr << "Error: epoll_wait" << std::endl;
            continue;
        }

        for (int n = 0; n < nfds; ++n) {
            if (events[n].data.fd == this->serverSocket) {
                // New connection
                sockaddr_storage clientAddress{};
                socklen_t clientAddressLength = sizeof(clientAddress);
                const int clientSocket = accept(this->serverSocket, reinterpret_cast<struct sockaddr *>(&clientAddress), &clientAddressLength);

                // If we have an error, but it's causing by stoping server stop this loop
                if (clientSocket < 0 && this->stopServer) {
                    break;
                }

                if (clientSocket < 0) {
                    std::cerr << "Error: Cannot accept client connection" << std::endl;
                    continue;
                }

                if (this->on_connect_callback_) {
                    this->on_connect_callback_(clientSocket, &clientAddress);
                }
            }
        }
    }
}

void invilite::Transport::TcpServer::onConnect(const OnConnectCallback &callback) {
    on_connect_callback_ = callback;
}
