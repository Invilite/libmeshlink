#ifndef TCP_SERVER_H
#define TCP_SERVER_H

#include <mutex>
#include <string>
#include <vector>
#include <thread>
#include <unistd.h>
#include <iostream>
#include <algorithm>
#include <functional>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include "ClientHandler.h"

namespace invilite {

class TcpServer {
public:
    TcpServer(const int port);
    virtual ~TcpServer();

    void start();
    std::vector<std::shared_ptr<ClientHandler>> get_clients();
    void sendTo(const std::shared_ptr<ClientHandler> &client, const std::string &data);

    using OnConnectCallback = std::function<void(const std::shared_ptr<ClientHandler> &client)>;
    using OnDisconnectCallback = std::function<void(const std::shared_ptr<ClientHandler> &client)>;
    using OnReceivedCallback = std::function<void(const std::shared_ptr<ClientHandler> &client, const std::string &data)>;

    void onConnect(const OnConnectCallback &callback);
    void onDisconnect(const OnDisconnectCallback &callback);
    void onDataReceived(const OnReceivedCallback &callback);

protected:
    virtual void on_client_connected(const std::shared_ptr<ClientHandler> &client);
    virtual void on_client_disconnected(const std::shared_ptr<ClientHandler> &client);
    virtual void on_data_received(const std::shared_ptr<ClientHandler> &client, const std::string &data);

private:
    void handle_client(const std::shared_ptr<ClientHandler> &client);

    const int port;
    int server_socket_;
    std::vector<std::shared_ptr<ClientHandler>> clients_;
    std::mutex clients_mutex_;

    OnConnectCallback on_connect_callback_;
    OnDisconnectCallback on_disconnect_callback_;
    OnReceivedCallback on_received_callback_;
};

}

#endif // TCP_SERVER_H
