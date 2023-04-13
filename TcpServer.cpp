#include "TcpServer.h"

invilite::TcpServer::TcpServer(const int port) : port(port), server_socket_(-1) {}

invilite::TcpServer::~TcpServer() {
    if (server_socket_ != -1) {
        close(server_socket_);
    }
}

void invilite::TcpServer::start() {
    server_socket_ = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket_ == -1) {
        std::cerr << "Error: Cannot create socket" << std::endl;
        return;
    }

    sockaddr_in server_address;
    server_address.sin_family = AF_INET;
    server_address.sin_addr.s_addr = INADDR_ANY;
    server_address.sin_port = htons(this->port);

    if (bind(server_socket_, (struct sockaddr *)&server_address, sizeof(server_address)) < 0) {
        std::cerr << "Error: Cannot bind socket" << std::endl;
        return;
    }

    if (listen(server_socket_, 5) < 0) {
        std::cerr << "Error: Cannot listen on socket" << std::endl;
        return;
    }

    std::cout << "Server listening on port " << this->port << std::endl;

    while (true) {
        sockaddr_in clientAddress;
        socklen_t clientAddressLength = sizeof(clientAddress);
        int clientSocket = accept(server_socket_, (struct sockaddr *)&clientAddress, &clientAddressLength);
        if (clientSocket < 0) {
            std::cerr << "Error: Cannot accept client connection" << std::endl;
            continue;
        }

        std::string clientIp = inet_ntoa(clientAddress.sin_addr);
        const int clientPort = ntohs(clientAddress.sin_port);
        std::cout << "Connected client: " << clientIp << ":" << clientPort << std::endl << std::flush;

        {
            std::unique_lock<std::mutex> lock(clients_mutex_);
            clients_.push_back(std::make_shared<ClientHandler>(clientSocket));
        }

        {
            std::unique_lock<std::mutex> lock(clients_info_mutex_);
            connected_clients_info_.insert(std::make_pair(clientIp, clientPort));
        }

        std::thread client_thread(&TcpServer::handle_client, this, clients_.back());
        client_thread.detach();
    }
}

std::vector<std::shared_ptr<invilite::ClientHandler>> invilite::TcpServer::getClients() {
    std::unique_lock<std::mutex> lock(clients_info_mutex_);
    return clients_;
}

void invilite::TcpServer::sendTo(const std::shared_ptr<ClientHandler> &client, const std::string &data) {
    send(client->getSocket(), data.c_str(), data.length(), 0);
}

std::set<std::pair<std::string, int>> invilite::TcpServer::getConnectedClientsInfo() const {
    std::unique_lock<std::mutex> lock(clients_info_mutex_);
    return connected_clients_info_;
}

bool invilite::TcpServer::isConnected(const std::string &address) const {
    std::unique_lock<std::mutex> lock(clients_info_mutex_);
    auto it = std::find_if(connected_clients_info_.begin(), connected_clients_info_.end(),
                           [&](const std::pair<std::string, int> &client_info) {
                               return client_info.first == address;
                           });
    return it != connected_clients_info_.end();
}

void invilite::TcpServer::onConnect(const OnConnectCallback &callback) {
    on_connect_callback_ = callback;
}

void invilite::TcpServer::onDisconnect(const OnDisconnectCallback &callback) {
    on_disconnect_callback_ = callback;
}

void invilite::TcpServer::onDataReceived(const OnReceivedCallback &callback) {
    on_received_callback_ = callback;
}

void invilite::TcpServer::on_client_connected(const std::shared_ptr<ClientHandler> &client) {
    if (on_connect_callback_) {
        on_connect_callback_(client);
    }
}

void invilite::TcpServer::on_client_disconnected(const std::shared_ptr<ClientHandler> &client) {
    if (on_disconnect_callback_) {
        on_disconnect_callback_(client);
    }
}

void invilite::TcpServer::on_data_received(const std::shared_ptr<ClientHandler> &client, const std::string &data) {
    if (on_received_callback_) {
        on_received_callback_(client, data);
    }
}

void invilite::TcpServer::handle_client(const std::shared_ptr<ClientHandler> &client) {
    on_client_connected(client);

    char buffer[1024];
    ssize_t bytes_received;
    while ((bytes_received = recv(client->getSocket(), buffer, sizeof(buffer), 0)) > 0) {
        std::string data(buffer, bytes_received);
        on_data_received(client, data);
    }

    on_client_disconnected(client);

    {
        std::unique_lock<std::mutex> lock(clients_info_mutex_);
        connected_clients_info_.erase(std::make_pair(client->getClientIp(), client->getClientPort()));
    }

    std::unique_lock<std::mutex> lock(clients_mutex_);
    auto it = std::find(clients_.begin(), clients_.end(), client);
    if (it != clients_.end()) {
        clients_.erase(it);
    }

    close(client->getSocket());
}
