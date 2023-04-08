#include "MeshProtocol.h"

invilite::MeshProtocol::MeshProtocol(const std::string* nodeId): nodeId(nodeId) {
	std::lock_guard<std::mutex> lock(nodes_mutex_);
}

void invilite::MeshProtocol::connectToNode(const std::string& address, const int port) {
    auto client = std::make_shared<TcpClient>();

    client->onConnect([this, client]() {
        NodeIdPacket nodeIdPacket(*this->nodeId);
        sendDataTo(client, nodeIdPacket);
    });

    client->onDataReceived([this, client](const std::string& data) {
        auto packetHeader = invilite::Serializer::getHeader(data);
        if (packetHeader == MeshPacket::NODE_ID_PACKET) {
        	NodeIdPacket nodeIdPacket = NodeIdPacket::unpack(data);
        	const std::string nodeId = nodeIdPacket.nodeId;

        	// Loop connection
        	if (nodeId == *this->nodeId) {
        		std::cout << "Loop connection detected, disconnecting!" << std::endl;
        		client->disconnect();
        	}

        	{
	            std::lock_guard<std::mutex> lock(nodes_mutex_);
	            outgoing_nodes_[nodeId] = client;
	        }

            onNodeConnected(nodeId);

	        client->onDisconnect([this, nodeId]() {
	            std::lock_guard<std::mutex> lock(nodes_mutex_);
	            outgoing_nodes_.erase(nodeId);
	            
	            onNodeDisconnected(nodeId);
	        });

	        client->onDataReceived([this, nodeId](const std::string& data) {
	        	auto packetHeader = invilite::Serializer::getHeader(data);
	        	switch(packetHeader) {
	        	case MeshPacket::NAMED_STRING_PACKET:
	        		NamedStringPacket namedStringPacket = NamedStringPacket::unpack(data);
	        		onDataReceived(nodeId, namedStringPacket.dataName, namedStringPacket.data);
	        		break;
	        	}
            });
        }
    });

    client->connect(address, port);
}

void invilite::MeshProtocol::sendDataTo(const std::string& nodeId, const std::string& dataName, const std::string& data) {
	NamedStringPacket namedStringPacket(dataName, data);
	sendDataTo(nodeId, namedStringPacket);
}

template <typename T>
void invilite::MeshProtocol::sendDataTo(const std::string& nodeId, T& packet) {
	// Find client
    std::lock_guard<std::mutex> lock(nodes_mutex_);
    auto it = outgoing_nodes_.find(nodeId);
    if (it != outgoing_nodes_.end()) {
        auto& client = it->second;
        sendDataTo(client, packet);
    } else {
        // Node not found, handle error if needed
    }
}

template <typename T>
void invilite::MeshProtocol::sendDataTo(std::shared_ptr<TcpClient> client, T& packet) {
	std::string packedData = packet.pack();
	client->send(packedData);
}

void invilite::MeshProtocol::onConnect(const std::shared_ptr<invilite::ClientHandler> &client) {
	std::cout << "Nowe połączenie!" << std::endl;
}

void invilite::MeshProtocol::onDisconnect(const std::shared_ptr<invilite::ClientHandler> &client) {
	std::cout << "Połączenie zakończone!" << std::endl;
}

void invilite::MeshProtocol::onServerDataReceived(const std::shared_ptr<invilite::ClientHandler> &client, const std::string &data) {
	auto header = invilite::Serializer::getHeader(data);

	switch(header) {
	case MeshPacket::NODE_ID_PACKET:
		{
			NodeIdPacket nodeIdPacket = NodeIdPacket::unpack(data);
			std::cout << "Nowy klient się przedstawił, jego nodeId to: " << nodeIdPacket.nodeId << std::endl;
			incomming_nodes_[nodeIdPacket.nodeId] = client;
			onNodeConnected(nodeIdPacket.nodeId);
		}
		{
			NodeIdPacket nodeIdPacket(*this->nodeId);
			std::string packedData = nodeIdPacket.pack();
        	client->send(packedData);
		}
		break;
	}
}
