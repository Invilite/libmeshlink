#include "ClientHandler.h"

invilite::ClientHandler::ClientHandler(int clientSocket): socket(clientSocket) {

}

int invilite::ClientHandler::getSocket() const {
    return socket;
}

void invilite::ClientHandler::send(const std::string& data) {
    if (socket != -1) {
        ::send(socket, data.c_str(), data.length(), 0);
    }
}
