#ifndef TCPCLIENT_H
#define TCPCLIENT_H

#include <mutex>
#include <atomic>
#include <thread>
#include <chrono>
#include <string>
#include <fcntl.h>
#include <unistd.h>
#include <iostream>
#include <sys/uio.h>
#include <functional>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

namespace invilite {

class TcpClient {
public:
    TcpClient();
    ~TcpClient();

    bool connect(const std::string& address, const int port, std::chrono::seconds timeout = std::chrono::seconds::max());
    void disconnect(); // Note: This is also called from the destructor.
    void onConnect(std::function<void(int clientSocket, const sockaddr_storage* clientAddress)> onConnect);

private:
    int clientSocket;
    std::function<void(int clientSocket, const sockaddr_storage* clientAddress)> onConnect_;
};

} // namespace invilite

#endif // TCPCLIENT_H
