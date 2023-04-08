#ifndef CLIENT_HANDLER_H
#define CLIENT_HANDLER_H

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

class ClientHandler {
public:
    ClientHandler(int client_socket);
    int getSocket() const;
    void send(const std::string& data);

protected:
    int socket;
};

}

#endif // CLIENT_HANDLER_H