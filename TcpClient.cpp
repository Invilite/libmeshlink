#include "TcpClient.h"

invilite::TcpClient::TcpClient() : clientSocket(-1) {}

invilite::TcpClient::~TcpClient() {
    disconnect();
}

bool invilite::TcpClient::connect(const std::string& address, const int port, std::chrono::seconds timeout) {
    // Creating a new socket
    clientSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (clientSocket < 0) {
        std::cerr << "Error: Cannot create socket" << std::endl;
        return false;
    }

    // Setting socket to non-blocking mode
    int flags = fcntl(clientSocket, F_GETFL, 0);
    if (flags < 0) {
        std::cerr << "Error: fcntl F_GETFL failed" << std::endl;
        close(clientSocket);
        clientSocket = -1;
        return false;
    }

    if (fcntl(clientSocket, F_SETFL, flags | O_NONBLOCK) < 0) {
        std::cerr << "Error: fcntl F_SETFL failed" << std::endl;
        close(clientSocket);
        clientSocket = -1;
        return false;
    }

    // Initiate connection
    sockaddr_in server_address;
    server_address.sin_family = AF_INET;
    server_address.sin_addr.s_addr = inet_addr(address.c_str());
    server_address.sin_port = htons(port);
    int connect_result = ::connect(clientSocket, (struct sockaddr *)&server_address, sizeof(server_address));

    // Jeśli połączenie nie zostanie zakończone natychmiast, sprawdź czy będzie dostępne w czasie określonym przez timeout
    if (connect_result == -1 && errno == EINPROGRESS) {
        fd_set writefds;
        FD_ZERO(&writefds);
        FD_SET(clientSocket, &writefds);

        timeval tv;
        tv.tv_sec = timeout.count();
        tv.tv_usec = 0;

        int select_result = select(clientSocket + 1, nullptr, &writefds, nullptr, &tv);

        if (select_result < 0) { // błąd select
            std::cerr << "Error: select failed" << std::endl;
            close(clientSocket);
            clientSocket = -1;
            return false;
        }

        if (select_result == 0) { // timeout
            std::cerr << "Error: Connection timed out" << std::endl;
            close(clientSocket);
            clientSocket = -1;
            return false;
        }

        // Sprawdź, czy połączenie zostało nawiązane poprawnie
        int error;
        socklen_t error_len = sizeof(error);
        getsockopt(clientSocket, SOL_SOCKET, SO_ERROR, &error, &error_len);

        if (error != 0) { // błąd podczas nawiązywania połączenia
            std::cerr << "Error: Connection failed" << std::endl;
            close(clientSocket);
            clientSocket = -1;
            return false;
        }
    } else if (connect_result == -1) { // błąd podczas próby połączenia
        std::cerr << "Error: Connection attempt failed" << std::endl;
        close(clientSocket);
        clientSocket = -1;
        return false;
    }

    // Restoring the blocking state of the socket
    flags = fcntl(clientSocket, F_GETFL, 0);
    if (flags < 0) {
        std::cerr << "Error: fcntl F_GETFL failed" << std::endl;
        close(clientSocket);
        clientSocket = -1;
        return false;
    }

    if (fcntl(clientSocket, F_SETFL, flags & ~O_NONBLOCK) < 0) {
        std::cerr << "Error: fcntl F_SETFL failed" << std::endl;
        close(clientSocket);
        clientSocket = -1;
        return false;
    }

    // Set KEEPALIVE option
    int enable = 1;
    if (setsockopt(clientSocket, SOL_SOCKET, SO_KEEPALIVE, &enable, sizeof(enable)) < 0) {
        std::cerr << "Error: setsockopt SO_KEEPALIVE failed" << std::endl;
        close(clientSocket);
        clientSocket = -1;
        return false;
    }

    // Get connection time
    connectedTimestamp = std::chrono::steady_clock::now();

    if (onConnect_) {
        onConnect_();
    }

    // Starting the data reception thread
    connected = true;
    receive_thread_ = std::thread(&TcpClient::receive_data, this);

    return true;
}

void invilite::TcpClient::disconnect() {
    // Requesting the receive_data thread to stop
    connected = false;

    // Shutting down the socket for reading and writing, socket will be fully closed in the receive_data thread
    if (clientSocket != -1) {
        shutdown(clientSocket, SHUT_RDWR);
    }

    // Waiting for the receive_data thread to stop
    if (receive_thread_.joinable()) {
        receive_thread_.join();
    }
}

bool invilite::TcpClient::isConnected() {
    return connected;
}

// TODO: This send method should call second send method
void invilite::TcpClient::send(const std::string& data) {
    if (clientSocket == -1) {
        std::cerr << "Error: socket is closed." << std::endl;
        return;
    }
    long unsigned int sentBytes = ::send(clientSocket, data.c_str(), data.length(), 0);
    if (sentBytes != data.length()) {
        std::cerr << "Error: not all bytes were sent" << std::endl;
    }
}

void invilite::TcpClient::send(const char* data, uint32_t dataLen) {
    if (clientSocket != -1) {
        ssize_t sentBytes = ::send(clientSocket, data, dataLen, 0);
        if (sentBytes != dataLen) {
            std::cerr << "Error: not all bytes were sent" << std::endl;
        }
    }
}

void invilite::TcpClient::onConnect(std::function<void()> onConnect) {
    onConnect_ = onConnect;
}

void invilite::TcpClient::onDisconnect(std::function<void()> onDisconnect) {
    onDisconnect_ = onDisconnect;
}

void invilite::TcpClient::onDataReceived(std::function<void(const std::string& data)> onData) {
    onData_ = onData;
}

void invilite::TcpClient::receive_data() {
    // Setting the thread name for debugging purposes
    pthread_setname_np(pthread_self(), "OutgoingConn");

    char buffer[1024];          // The buffer for received data
    ssize_t bytes_received;     // The number of bytes received in the last recv call

    // Start the main receive loop
    while (connected) {
        bytes_received = recv(clientSocket, buffer, sizeof(buffer), 0);
        if (bytes_received > 0) {
            // Data received
            std::string data(buffer, bytes_received);
            if (onData_) {
                onData_(data);
            }
        } else if (bytes_received == 0) {
            // Serwer zamknął połączenie
            break;
        } else {
            // Wystąpił błąd podczas odbierania danych
            perror("recv error");
            break;
        }
    }
    connected = false;

    // Notifying about the disconnection
    if (onDisconnect_) {
        onDisconnect_();
    }

    // Shutting down and closing the socket
    shutdown(clientSocket, SHUT_RDWR);
    close(clientSocket);
    clientSocket = -1;
}

unsigned int invilite::TcpClient::getConnectionTime() const {
    auto now = std::chrono::steady_clock::now();
    auto elapsedDuration = now - connectedTimestamp;
    return std::chrono::duration_cast<std::chrono::seconds>(elapsedDuration).count();
}