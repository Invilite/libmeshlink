#include "TcpServer.h"

invilite::TcpServer::TcpServer(const int port) : serverPort(port), serverSocket(-1) {}

invilite::TcpServer::~TcpServer() {
    if (serverSocket != -1) {
        close(serverSocket);
    }
}

int invilite::TcpServer::start() {
    // Stop server if running
    this->stop();

    // Create new server socket
    this->serverSocket = socket(AF_INET6, SOCK_STREAM, 0);
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

    // Enable dual-stack (IPv4 and IPv6)
    opt = 0;
    if (setsockopt(this->serverSocket, IPPROTO_IPV6, IPV6_V6ONLY, &opt, sizeof(opt)) < 0) {
        perror("setsockopt");
        return -5;
    }

    // sockaddr_in server_address;
    // server_address.sin_family = AF_INET;
    // server_address.sin_addr.s_addr = INADDR_ANY;
    // server_address.sin_port = htons(this->serverPort);

    sockaddr_in6 server_address;
    memset(&server_address, 0, sizeof(server_address));
    server_address.sin6_family = AF_INET6;
    server_address.sin6_addr = in6addr_any; // Akceptuj połączenia IPv6
    server_address.sin6_port = htons(this->serverPort);

    if (bind(this->serverSocket, (struct sockaddr *)&server_address, sizeof(server_address)) < 0) {
        std::cerr << "Error: Cannot bind socket" << std::endl;
        return -6;
    }

    if (listen(this->serverSocket, 5) < 0) {
        std::cerr << "Error: Cannot listen on socket" << std::endl;
        return -7;
    }

    std::cout << "Server listening on port " << this->serverPort << std::endl;

    // Start server accept thread
    this->stopServer = false;
    this->serverThread = std::thread(&TcpServer::server_thread, this);
    pthread_setname_np(this->serverThread.native_handle(), "TcpServer");

    return 0;
}

void invilite::TcpServer::stop() {
    // Stop server thread
    this->stopServer = true;

    // Close server socket
    if (this->serverSocket != -1) {
        shutdown(this->serverSocket, SHUT_RDWR);
        close(this->serverSocket);
        this->serverSocket = -1;
    }

    // Wait for server thread to finish
    if (this->serverThread.joinable()) {
        this->serverThread.join();
    }
}

void invilite::TcpServer::server_thread () {
    fd_set read_fds;
    FD_ZERO(&read_fds);
    FD_SET(this->serverSocket, &read_fds);

    while (!this->stopServer) {
        fd_set current_fds = read_fds; // Copy fd set, select may alter it.

        // Set up timeout for select.
        struct timeval receiveTimeout;
        receiveTimeout.tv_sec = 1;  // Set timeout to 1 second.
        receiveTimeout.tv_usec = 0;

        // Wait for a connection, but only for the timeout duration.
        if (select(this->serverSocket + 1, &current_fds, NULL, NULL, &receiveTimeout) > 0) {
            if (!FD_ISSET(this->serverSocket, &read_fds)) {
                continue;
            }

            // New connection
            sockaddr_storage clientAddress;
            socklen_t clientAddressLength = sizeof(clientAddress);
            int clientSocket = accept(this->serverSocket, (struct sockaddr *)&clientAddress, &clientAddressLength);

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

void invilite::TcpServer::onConnect(const OnConnectCallback &callback) {
    on_connect_callback_ = callback;
}
