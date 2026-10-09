#ifndef TCP_SERVER_H
#define TCP_SERVER_H

#include <atomic>
#include <string>
#include <thread>
#include <utility>
#include <string.h>
#include <unistd.h>
#include <cstdint>
#include <string_view>
#include <functional>
#include <arpa/inet.h>
#include <sys/socket.h>

#include "transport/platform.h"

namespace invilite::Transport {

// Why start() failed. Transport does not log: the owner (Network) logs it with its own context.
enum class ListenError : uint8_t { None, InvalidAddress, SocketCreation, SocketOption, Bind, Listen, NonBlocking, WakeupSignal };

std::string_view listenErrorName(ListenError error);

struct ListenStartResult {
    ListenError error       = ListenError::None;
    int         errorNumber = 0;                                                        // errno of the failing call (0 if none)

    explicit operator bool() const { return this->error == ListenError::None; }
};

// Failure of the accept thread after a successful start(): reported through onListenerFailure, since that thread
// has no caller to return an error to.
enum class ListenerFailure : uint8_t {
    PollFailed,                                                                         // the accept loop stopped: no more inbound connections
    AcceptFailed,                                                                       // one accept() failed (e.g. out of descriptors); the loop goes on
};

class TcpServer {
public:
    // listenAddress must be a numeric IPv4/IPv6 address (no DNS): "::" = every interface over IPv4 and IPv6 (dual stack),
    // "0.0.0.0" = every IPv4 interface, any other address = only that interface (e.g. a VPN). backlog is passed to listen().
    TcpServer(std::string listenAddress, int port, int backlog);
    virtual ~TcpServer();

    ListenStartResult start();
    void stop();

    using OnConnectCallback = std::function<void(int clientSocket, const sockaddr_storage* clientAddress)>;
    void onConnect(const OnConnectCallback &callback);

    // Called from the accept thread; set it before start()
    using OnListenerFailureCallback = std::function<void(ListenerFailure failure, int errorNumber)>;
    void onListenerFailure(const OnListenerFailureCallback& callback);

protected:

private:
    void serverListener();

    const std::string listenAddress;
    const int serverPort;
    const int backlog;
    int serverSocket;
    std::atomic<bool> stopServer = false;
    std::thread serverThread;
    Platform::WakeupSignal stopSignal;                                                  // wakes serverListener on stop(): no reliance on shutdown() waking poll()

    OnConnectCallback         on_connect_callback_;
    OnListenerFailureCallback onListenerFailureCallback;
};

} // namespace invilite::Transport

#endif // TCP_SERVER_H
