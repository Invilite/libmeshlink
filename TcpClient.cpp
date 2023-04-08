#include "TcpClient.h"

namespace invilite {

TcpClient::TcpClient() : client_socket_(-1) {}

TcpClient::~TcpClient() {
    disconnect();
}

bool TcpClient::connect(const std::string& address, const int port) {
    disconnect();

    client_socket_ = socket(AF_INET, SOCK_STREAM, 0);
    if (client_socket_ < 0) {
        std::cerr << "Error: Cannot create socket" << std::endl;
        return false;
    }

    int enable = 1;
    setsockopt(client_socket_, IPPROTO_TCP, TCP_KEEPIDLE, &enable, sizeof(enable));

    sockaddr_in server_address;
    server_address.sin_family = AF_INET;
    server_address.sin_addr.s_addr = inet_addr(address.c_str());
    server_address.sin_port = htons(port);

    if (::connect(client_socket_, (struct sockaddr*)&server_address, sizeof(server_address)) < 0) {
        std::cerr << "Error: Cannot connect to server" << std::endl;
        close(client_socket_);
        client_socket_ = -1;
        return false;
    }

    if (onConnect_) {
        onConnect_();
    }

    should_disconnect_ = false;

    std::thread connection_thread(&TcpClient::receive_data, this);
    connection_thread.detach();

    return true;
}

bool TcpClient::connect(const std::string &address, const int port, std::chrono::seconds timeout) {
    if (client_socket_ != -1) {
        return false;
    }

    client_socket_ = socket(AF_INET, SOCK_STREAM, 0);
    if (client_socket_ == -1) {
        return false;
    }

    sockaddr_in server_address;
    server_address.sin_family = AF_INET;
    server_address.sin_addr.s_addr = inet_addr(address.c_str());
    server_address.sin_port = htons(port);

    // Ustawianie opcji gniazda na nieblokujące
    int flags = fcntl(client_socket_, F_GETFL, 0);
    fcntl(client_socket_, F_SETFL, flags | O_NONBLOCK);

    // Próba połączenia
    int connect_result = ::connect(client_socket_, (struct sockaddr *)&server_address, sizeof(server_address));

    // Jeśli połączenie nie zostanie zakończone natychmiast, sprawdź czy będzie dostępne w czasie określonym przez timeout
    if (connect_result == -1 && errno == EINPROGRESS) {
        fd_set writefds;
        FD_ZERO(&writefds);
        FD_SET(client_socket_, &writefds);

        timeval tv;
        tv.tv_sec = timeout.count();
        tv.tv_usec = 0;

        int select_result = select(client_socket_ + 1, nullptr, &writefds, nullptr, &tv);

        if (select_result <= 0) { // timeout lub błąd
            close(client_socket_);
            client_socket_ = -1;
            return false;
        }

        // Sprawdź, czy połączenie zostało nawiązane poprawnie
        int error;
        socklen_t error_len = sizeof(error);
        getsockopt(client_socket_, SOL_SOCKET, SO_ERROR, &error, &error_len);

        if (error != 0) { // błąd podczas nawiązywania połączenia
            close(client_socket_);
            client_socket_ = -1;
            return false;
        }
    } else if (connect_result == -1) { // błąd podczas próby połączenia
        close(client_socket_);
        client_socket_ = -1;
        return false;
    }

    // Przywróć blokujące gniazdo
    flags = fcntl(client_socket_, F_GETFL, 0);
    fcntl(client_socket_, F_SETFL, flags & ~O_NONBLOCK);

    // Ustawianie opcji KEEPALIVE
    int enable = 1;
    setsockopt(client_socket_, SOL_SOCKET, SO_KEEPALIVE, &enable, sizeof(enable));

    should_disconnect_ = false;

    // Uruchom wątek odbierający dane
    receive_thread_ = std::thread(&TcpClient::receive_data, this);

    if (onConnect_) {
        onConnect_();
    }

    return true;
}

void TcpClient::disconnect() {
    should_disconnect_ = true;
    if (receive_thread_.joinable()) {
        receive_thread_.join();
    }
    close(client_socket_);
    client_socket_ = -1;
    if (onDisconnect_) {
        onDisconnect_();
    }
}

void TcpClient::send(const std::string& data) {
    if (client_socket_ != -1) {
        ::send(client_socket_, data.c_str(), data.length(), 0);
    }
}

void TcpClient::send(const char* data, uint32_t dataLen) {
    if (client_socket_ != -1) {
        ::send(client_socket_, data, dataLen, 0);
    }
}

void TcpClient::onConnect(std::function<void()> onConnect) {
    onConnect_ = onConnect;
}

void TcpClient::onDisconnect(std::function<void()> onDisconnect) {
    onDisconnect_ = onDisconnect;
}

void TcpClient::onDataReceived(std::function<void(const std::string& data)> onData) {
    onData_ = onData;
}

void TcpClient::receive_data() {
    char buffer[1024];
    ssize_t bytes_received;
    while (!should_disconnect_) {
        bytes_received = recv(client_socket_, buffer, sizeof(buffer), 0);
        if (bytes_received > 0) {
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
}

} // namespace invilite