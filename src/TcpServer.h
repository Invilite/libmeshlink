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
#include <string.h>
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

    int start();
    void stop();
    void sendTo(const std::shared_ptr<ClientHandler> &client, const std::string &data);

    using OnConnectCallback = std::function<void(int clientSocket, sockaddr_storage* clientAddress)>;
    void onConnect(const OnConnectCallback &callback);

protected:

private:
    void server_thread();

    const int serverPort;
    int serverSocket;
    std::atomic<bool> stopServer = false;
    std::thread serverThread;

    OnConnectCallback on_connect_callback_;
};

}

#endif // TCP_SERVER_H
