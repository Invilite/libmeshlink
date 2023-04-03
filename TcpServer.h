#ifndef TCP_SERVER_H
#define TCP_SERVER_H

#include <iostream>
#include <string>
#include <vector>
#include <thread>
#include <mutex>
#include <algorithm>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include "ClientHandler.h"

namespace invilite {

class TcpServer {
public:
    TcpServer(const int port);
    virtual ~TcpServer();

    void start();
    std::vector<std::shared_ptr<ClientHandler>> get_clients();
    void send_to_client(const std::shared_ptr<ClientHandler> &client, const std::string &data);

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
};

}

#endif // TCP_SERVER_H
