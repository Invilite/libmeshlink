#ifndef TCPCLIENT_H
#define TCPCLIENT_H

#include <chrono>
#include <cstdint>
#include <string_view>
#include <string>
#include <functional>
#include <sys/socket.h>

namespace invilite::Transport {

    // Why connect() failed. Transport does not log: the caller (Network) logs it with its own context.
    enum class ConnectError : uint8_t {
        None,
        AlreadyConnected,
        ResolveFailed,                                                                  // getaddrinfo failed
        SocketCreation,
        NonBlocking,
        KeepAlive,                                                                      // setsockopt SO_KEEPALIVE failed
        ConnectFailed,                                                                  // connect attempt failed
        PollFailed,
        TimedOut,
        Refused,                                                                        // connect error reported by SO_ERROR
    };

    std::string_view connectErrorName(ConnectError error);

    class TcpClient {
    public:
        TcpClient();
        ~TcpClient();

        TcpClient(const TcpClient&)            = delete;
        TcpClient& operator=(const TcpClient&) = delete;

        // Connect to address — accepts IPv4, IPv6, or hostname (resolved via getaddrinfo).
        // An exception thrown by the onConnect callback propagates to the caller.
        ConnectError connect(const std::string& address, int port, std::chrono::seconds timeout = std::chrono::seconds(5));

        // Close and release the socket. Also called automatically from destructor.
        void disconnect();

        // Transfer ownership of the connected socket to the caller.
        // After this call, TcpClient no longer owns the socket — it will NOT close it
        // on disconnect()/destructor. Returns -1 if no socket is held.
        int release();

        // Callback invoked once after successful connect, from within connect(); exceptions propagate out of connect().
        // At the time of the callback the socket is still owned by TcpClient —
        // the caller should call release() if they want to take ownership.
        void onConnect(std::function<void(int clientSocket, const sockaddr_storage* clientAddress)> cb);

    private:
        int                                                                    clientSocket;
        std::function<void(int clientSocket, const sockaddr_storage*)>         onConnect_;
    };

} // namespace invilite::Transport

#endif // TCPCLIENT_H