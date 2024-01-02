#include "TcpClient.h"

invilite::TcpClient::TcpClient() : clientSocket(-1) {}

invilite::TcpClient::~TcpClient() {
    disconnect();
}

bool invilite::TcpClient::connect(const std::string& address, const int port, std::chrono::seconds timeout) {
    // Creating a new socket
    this->clientSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (this->clientSocket < 0) {
        std::cerr << "Error: Cannot create socket" << std::endl;
        return false;
    }

    // Setting socket to non-blocking mode
    int flags = fcntl(this->clientSocket, F_GETFL, 0);
    if (flags < 0) {
        std::cerr << "Error: fcntl F_GETFL failed" << std::endl;
        this->disconnect();
        return false;
    }

    if (fcntl(this->clientSocket, F_SETFL, flags | O_NONBLOCK) < 0) {
        std::cerr << "Error: fcntl F_SETFL failed" << std::endl;
        this->disconnect();
        return false;
    }

    // Initiate connection
    sockaddr_in server_address;
    server_address.sin_family = AF_INET;
    server_address.sin_addr.s_addr = inet_addr(address.c_str());
    server_address.sin_port = htons(port);
    int connect_result = ::connect(this->clientSocket, (struct sockaddr *)&server_address, sizeof(server_address));

    // Jeśli połączenie nie zostanie zakończone natychmiast, sprawdź czy będzie dostępne w czasie określonym przez timeout
    if (connect_result == -1 && errno == EINPROGRESS) {
        fd_set writefds;
        FD_ZERO(&writefds);
        FD_SET(this->clientSocket, &writefds);

        timeval tv;
        tv.tv_sec = timeout.count();
        tv.tv_usec = 0;

        int select_result = select(this->clientSocket + 1, nullptr, &writefds, nullptr, &tv);

        if (select_result < 0) { // błąd select
            std::cerr << "Error: select failed" << std::endl;
            this->disconnect();
            return false;
        }

        if (select_result == 0) { // timeout
            std::cerr << "Error: Connection timed out" << std::endl;
            this->disconnect();
            return false;
        }

        // Sprawdź, czy połączenie zostało nawiązane poprawnie
        int error;
        socklen_t error_len = sizeof(error);
        getsockopt(this->clientSocket, SOL_SOCKET, SO_ERROR, &error, &error_len);

        if (error != 0) { // błąd podczas nawiązywania połączenia
            std::cerr << "Error: Connection failed" << std::endl;
            this->disconnect();
            return false;
        }
    } else if (connect_result == -1) { // błąd podczas próby połączenia
        std::cerr << "Error: Connection attempt failed" << std::endl;
        this->disconnect();
        return false;
    }

    // Restoring the blocking state of the socket
    flags = fcntl(this->clientSocket, F_GETFL, 0);
    if (flags < 0) {
        std::cerr << "Error: fcntl F_GETFL failed" << std::endl;
        this->disconnect();
        return false;
    }

    if (fcntl(this->clientSocket, F_SETFL, flags & ~O_NONBLOCK) < 0) {
        std::cerr << "Error: fcntl F_SETFL failed" << std::endl;
        this->disconnect();
        return false;
    }

    // Set KEEPALIVE option
    int enable = 1;
    if (setsockopt(this->clientSocket, SOL_SOCKET, SO_KEEPALIVE, &enable, sizeof(enable)) < 0) {
        std::cerr << "Error: setsockopt SO_KEEPALIVE failed" << std::endl;
        this->disconnect();
        return false;
    }

    if (onConnect_) {
        onConnect_(this->clientSocket);
    }

    return true;
}

void invilite::TcpClient::disconnect() {
    if (this->clientSocket != -1) {
        shutdown(this->clientSocket, SHUT_RDWR);
        close(this->clientSocket);
        this->clientSocket = -1;
    }
}

void invilite::TcpClient::onConnect(std::function<void(int clientSocket)> onConnect) {
    onConnect_ = onConnect;
}
