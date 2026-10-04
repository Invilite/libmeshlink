#ifndef TCP_SERVER_H
#define TCP_SERVER_H

#include <atomic>
#include <string>
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
    // listenAddress must be a numeric IPv4/IPv6 address (no DNS): "::" = every interface over IPv4 and IPv6 (dual stack),
    // "0.0.0.0" = every IPv4 interface, any other address = only that interface (e.g. a VPN). backlog is passed to listen().
    TcpServer(std::string listenAddress, int port, int backlog);
    virtual ~TcpServer();

    int start();
    void stop();

    using OnConnectCallback = std::function<void(int clientSocket, const sockaddr_storage* clientAddress)>;
    void onConnect(const OnConnectCallback &callback);

protected:

private:
    void serverListener();

    const std::string listenAddress;
    const int serverPort;
    const int backlog;
    int serverSocket;
    std::atomic<bool> stopServer = false;
    std::thread serverThread;

    OnConnectCallback on_connect_callback_;
};

} // namespace invilite::Transport

#endif // TCP_SERVER_H
