#include <unistd.h> // usleep
#include <iostream>
#include <string>
#include <set>
#include <mutex>
#include <vector>
#include <chrono>
#include <algorithm>
#include <condition_variable>
#include "Mesh.h"

invilite::Mesh::Mesh(const std::string* nodeId, NodeList* nodeList_): MeshProtocol(nodeId), server(std::make_shared<invilite::TcpServer>(8420)), nodeList(nodeList_) {
    localConnectionsLimit = 1;
    globalConnectionsLimit = 5;

	// Handle server connections
	server->onConnect([this](const std::shared_ptr<invilite::ClientHandler> &client) {
        this->onConnect(client);
    });

    server->onDisconnect([this](const std::shared_ptr<invilite::ClientHandler> &client) {
        this->onDisconnect(client);
    });

    server->onDataReceived([this](const std::shared_ptr<invilite::ClientHandler> &client, const std::string &data) {
        this->onServerDataReceived(client, data);
    });
}

void invilite::Mesh::start() {
	// Start TCP server
	serverThread = std::thread(&invilite::TcpServer::start, server);
    serverThread.detach();

    // std::cout << "Connecting to nodes ..." << std::endl;
    // const std::set<std::string>& allEntries = nodeList->getAll();

    // for (const std::string& entry: allEntries) {
    //     std::cout << "Connecting to: " << entry << std::endl;
    //     connectToNode(entry, 8420);
    // }

    // Start updateConnections thread
    updateConnectionsThread = std::thread(&invilite::Mesh::updateConnections, this);
    updateConnectionsThread.detach();
}

void invilite::Mesh::stop() {
    if(serverThread.joinable()) {
        serverThread.join();
    }

    if(updateConnectionsThread.joinable()) {
        updateConnectionsThread.join();
    }
}

void invilite::Mesh::updateConnections() {
    while (true) {
        std::this_thread::sleep_for(std::chrono::milliseconds(500));

        const std::set<std::string>& allEntries = nodeList->getAll();
        connectToAvailableNodes(allEntries);
    }
}

void invilite::Mesh::connectToAvailableNodes(const std::set<std::string>& allEntries) {
    for (const std::string& address: allEntries) {
        // Skip nodes already connected to us
        if (server->isConnected(address)) {
            continue;
        }

        // Skip nodes that we already are connected
        if (connectedAddresses.count(address)) {
            continue;
        }

        if (invilite::IpTools::isLocalNetworkAddress(address)) {
            std::cout << "Connecting to local node: " << address << std::endl;
            connectToNode(address, 8420);
        } else {
            std::cout << "Connecting to global node: " << address << std::endl;
            connectToNode(address, 8420);
        }
    }
}

void invilite::Mesh::addNode(const std::string& address, const int port) {
    nodeList->add(address);
}

void invilite::Mesh::onNodeConnected(const std::string &nodeId) {
    std::cout << "New mesh node connected: " << nodeId << std::endl;

    sendDataTo(nodeId, "example-foo", "Lorem ipsum, fucking working");
}

void invilite::Mesh::onNodeDisconnected(const std::string &nodeId) {
    std::cout << "New mesh node disconnected: " << nodeId << std::endl;
}

void invilite::Mesh::onDataReceived(const std::string& nodeId, const std::string& dataName, const std::string& message) {
	std::cout << "Data received from node: " << nodeId << ", data name: " << dataName << ", data: " << message << std::endl;
}

std::shared_ptr<invilite::TcpClient> invilite::Mesh::getLongestConnectedClient() {
    std::shared_ptr<invilite::TcpClient> oldest_client = nullptr;
    unsigned int max_connection_time = 0;

    for (const auto& client : clients) {
        unsigned int connection_time = client->getConnectionTime();
        if (connection_time > max_connection_time) {
            max_connection_time = connection_time;
            oldest_client = client;
        }
    }

    return oldest_client;
}
