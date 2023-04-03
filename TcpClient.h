#ifndef TCPCLIENT_H
#define TCPCLIENT_H

#include <atomic>
#include <iostream>
#include <thread>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <fcntl.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/select.h>
#include <string>
#include <functional>
#include <mutex>

namespace invilite {

class TcpClient {
public:
    TcpClient();
    ~TcpClient();

    bool connect(const std::string& address, const int port);
    bool connect(const std::string& address, const int port, std::chrono::seconds timeout);
    void disconnect();
    void send(const std::string& data);

    void setOnConnectCallback(std::function<void()> onConnect);
    void setOnDisconnectCallback(std::function<void()> onDisconnect);
    void setOnDataCallback(std::function<void(const std::string& data)> onData);

private:
    void receive_data();

    int client_socket_;
    std::mutex socket_mutex_;
    std::thread receive_thread_;
    std::atomic<bool> should_disconnect_;

    std::function<void()> onConnect_;
    std::function<void()> onDisconnect_;
    std::function<void(const std::string& data)> onData_;
};

} // namespace invilite

#endif // TCPCLIENT_H
