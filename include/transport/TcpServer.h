#ifndef TCP_SERVER_H
#define TCP_SERVER_H

#include <atomic>
#include <thread>
#include <utility>
#include <string.h>
#include <unistd.h>
#include <iostream>
#include <functional>
#include <arpa/inet.h>
#include <sys/epoll.h>
#include <sys/socket.h>

namespace invilite::Transport {

class TcpServer {
public:
    TcpServer(const int port);
    virtual ~TcpServer();

    int start();
    void stop();

    using OnConnectCallback = std::function<void(int clientSocket, const sockaddr_storage* clientAddress)>;
    void onConnect(const OnConnectCallback &callback);

protected:

private:
    void serverListener();

    const int serverPort;
    int serverSocket;
    std::atomic<bool> stopServer = false;
    std::thread serverThread;

    OnConnectCallback on_connect_callback_;
};

} // namespace invilite::Transport

#endif // TCP_SERVER_H
