#ifndef TCPCLIENT_H
#define TCPCLIENT_H

#include <chrono>
#include <fcntl.h>
#include <unistd.h>
#include <iostream>
#include <functional>
#include <arpa/inet.h>
#include <sys/socket.h>

namespace invilite {

// enum TCP_CLIENT_ERROR {
//     spring = 0, 
//     summer = 4, 
//     autumn = 8,
//     winter = 12
// };

class TcpClient {
public:
    TcpClient();
    ~TcpClient();

    uint8_t connect(const std::string& address, const int port, std::chrono::seconds timeout = std::chrono::seconds::max());
    void disconnect(); // Note: This is also called from the destructor.
    void onConnect(std::function<void(int clientSocket, const sockaddr_storage* clientAddress)> onConnect);

private:
    int clientSocket;
    std::function<void(int clientSocket, const sockaddr_storage* clientAddress)> onConnect_;
};

} // namespace invilite

#endif // TCPCLIENT_H
