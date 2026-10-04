#ifndef TCPCLIENT_H
#define TCPCLIENT_H

#include <chrono>
#include <string>
#include <functional>
#include <sys/socket.h>

namespace invilite::Transport {

    class TcpClient {
    public:
        TcpClient();
        ~TcpClient();

        TcpClient(const TcpClient&)            = delete;
        TcpClient& operator=(const TcpClient&) = delete;

        // Connect to address — accepts IPv4, IPv6, or hostname (resolved via getaddrinfo).
        // Returns 0 on success, non-zero error code otherwise.
        // Error codes:
        //   1    already connected
        //   2    address resolution (getaddrinfo) failed
        //   3    socket() failed
        //   10   fcntl F_GETFL failed
        //   11   fcntl F_SETFL failed
        //   14   setsockopt SO_KEEPALIVE failed
        //   100  connect attempt failed
        //   101  select failed
        //   102  connection timed out
        //   103  connect error reported by SO_ERROR
        uint8_t connect(const std::string& address, int port, std::chrono::seconds timeout = std::chrono::seconds(5));

        // Close and release the socket. Also called automatically from destructor.
        void disconnect();

        // Transfer ownership of the connected socket to the caller.
        // After this call, TcpClient no longer owns the socket — it will NOT close it
        // on disconnect()/destructor. Returns -1 if no socket is held.
        int release();

        // Callback invoked once after successful connect, from within connect().
        // At the time of the callback the socket is still owned by TcpClient —
        // the caller should call release() if they want to take ownership.
        void onConnect(std::function<void(int clientSocket, const sockaddr_storage* clientAddress)> cb);

    private:
        int                                                                    clientSocket;
        std::function<void(int clientSocket, const sockaddr_storage*)>         onConnect_;
    };

} // namespace invilite::Transport

#endif // TCPCLIENT_H