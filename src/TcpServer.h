#ifndef TCP_SERVER_H
#define TCP_SERVER_H

#include <set>
#include <mutex>
#include <atomic>
#include <string>
#include <vector>
#include <memory>
#include <thread>
#include <utility>
#include <unistd.h>
#include <iostream>
#include <algorithm>
#include <functional>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include "ClientHandler.h"
#include "debug.h"

namespace invilite {

class TcpServer {
public:
    TcpServer(const int port);
    virtual ~TcpServer();

    void start();
    void stop();
    std::vector<std::shared_ptr<ClientHandler>> getClients();
    void sendTo(const std::shared_ptr<ClientHandler> &client, const std::string &data);

    using OnConnectCallback = std::function<void(const std::shared_ptr<ClientHandler> &client)>;
    using OnDisconnectCallback = std::function<void(const std::shared_ptr<ClientHandler> &client)>;
    using OnReceivedCallback = std::function<void(const std::shared_ptr<ClientHandler> &client, const std::string &data)>;

    void onConnect(const OnConnectCallback &callback);
    void onDisconnect(const OnDisconnectCallback &callback);
    void onDataReceived(const OnReceivedCallback &callback);

    std::set<std::pair<std::string, int>> getConnectedClientsInfo() const;
    bool isConnected(const std::string &address) const;
    unsigned int getConnectionsCount();

protected:
    virtual void on_client_connected(const std::shared_ptr<ClientHandler> &client);
    virtual void on_client_disconnected(const std::shared_ptr<ClientHandler> &client);
    virtual void on_data_received(const std::shared_ptr<ClientHandler> &client, const std::string &data);

private:
    static const std::array<uint16_t, 256> crc16Table;
    static std::array<uint16_t, 256> generateCRC16Table();
    static uint16_t calculateCRC16(const std::vector<uint8_t>& data);
    void handle_client(const std::shared_ptr<ClientHandler> &client);

    std::atomic<bool> stopServer = false;
    const int port;
    int server_socket_;
    std::vector<std::shared_ptr<ClientHandler>> clients_;
    std::mutex clients_mutex_;

    std::set<std::pair<std::string, int>> connected_clients_info_;
    mutable std::mutex clients_info_mutex_;

    OnConnectCallback on_connect_callback_;
    OnDisconnectCallback on_disconnect_callback_;
    OnReceivedCallback on_received_callback_;
};

}

#endif // TCP_SERVER_H
