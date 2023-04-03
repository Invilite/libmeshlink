#include "ClientHandler.h"

invilite::ClientHandler::ClientHandler(int clientSocket): socket(clientSocket) {

}

int invilite::ClientHandler::getSocket() const {
    return socket;
}