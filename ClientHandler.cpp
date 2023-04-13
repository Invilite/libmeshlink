#include "ClientHandler.h"

invilite::ClientHandler::ClientHandler(int clientSocket): socket(clientSocket) {
    socklen_t addr_size = sizeof(client_addr);
    getpeername(socket, reinterpret_cast<sockaddr*>(&client_addr), &addr_size);
}

int invilite::ClientHandler::getSocket() const {
    return socket;
}

void invilite::ClientHandler::send(const std::string& data) {
    if (socket != -1) {
        ::send(socket, data.c_str(), data.length(), 0);
    }
}

std::string invilite::ClientHandler::getClientIp() const {
    char ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(client_addr.sin_addr), ip, INET_ADDRSTRLEN);
    return std::string(ip);
}

int invilite::ClientHandler::getClientPort() const {
    return ntohs(client_addr.sin_port);
}
