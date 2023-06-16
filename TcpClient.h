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
    void disconnect();
    void send(const std::string& data);
    void send(const char* data, uint32_t dataLen);

    void onConnect(std::function<void()> onConnect);
    void onDisconnect(std::function<void()> onDisconnect);
    void onDataReceived(std::function<void(const std::string& data)> onData);

    unsigned int getConnectionTime() const;

private:
    void receive_data();

    int client_socket_;
    std::mutex socket_mutex_;
    std::thread receive_thread_;
    std::atomic<bool> should_disconnect_;

    std::function<void()> onConnect_;
    std::function<void()> onDisconnect_;
    std::function<void(const std::string& data)> onData_;

    // Connection time
    std::chrono::time_point<std::chrono::steady_clock> connectedTimestamp;
};

} // namespace invilite

#endif // TCPCLIENT_H
