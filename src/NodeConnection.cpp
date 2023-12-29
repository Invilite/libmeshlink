#include "NodeConnection.h"

invilite::NodeConnection::NodeConnection(const std::string& address, uint16_t port) {
	tcpClient = std::make_shared<TcpClient>();

	tcpClient->connect(address, port);
}