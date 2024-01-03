#include <set>
#include <list>
#include <mutex>
#include <string>
#include <vector>
#include <chrono>
#include <unistd.h> // usleep
#include <iostream>
#include <algorithm>
#include <condition_variable>
#include "Mesh.h"

using namespace invilite;
using std::make_shared;

Mesh::Mesh(const uint16_t port, const ClientId* nodeId, const std::vector<uint32_t> networkSecretKey): server(make_shared<TcpServer>(port)), nodeId(nodeId) {
    this->networkSecret.resize(networkSecretKey.size() * sizeof(uint32_t));
    std::memcpy(this->networkSecret.BytePtr(), networkSecretKey.data(), this->networkSecret.size());

	// Handle server connections
	server->onConnect([this](int clientSocket, sockaddr_storage* clientAddress) {

        char addressBuffer[INET6_ADDRSTRLEN];
        uint16_t port;

        if (clientAddress->ss_family == AF_INET) {
            // Przychodzące połączenie IPv4
            const sockaddr_in* addr4 = reinterpret_cast<const sockaddr_in*>(clientAddress);
            inet_ntop(AF_INET, &addr4->sin_addr, addressBuffer, sizeof(addressBuffer));
            port = ntohs(addr4->sin_port);
            spdlog::debug("onConnect: Incomming IPv4 connection from {} on port {}", addressBuffer, port);
        } else if (clientAddress->ss_family == AF_INET6) {
            // Przychodzące połączenie IPv6
            const sockaddr_in6* addr6 = reinterpret_cast<const sockaddr_in6*>(clientAddress);
            inet_ntop(AF_INET6, &addr6->sin6_addr, addressBuffer, sizeof(addressBuffer));
            port = ntohs(addr6->sin6_port);
            spdlog::debug("onConnect: Incomming IPv6 connection from {} on port {}", addressBuffer, port);
        } else {
            // Nieznany typ adresu
            spdlog::error("onConnect: Incomming connection unknown address family");
        }

        std::shared_ptr<NodeConnection> incommingConnection = std::make_shared<NodeConnection>(clientSocket, this->nodeId, this->networkSecret);

        std::lock_guard<std::mutex> lock(this->incommingConnectionsMutex);
        this->incommingConnections[clientSocket] = incommingConnection;

        auto onDisconnect = [this, clientSocket]() {
            std::lock_guard<std::mutex> lock(this->incommingConnectionsMutex);
            this->incommingConnections.erase(clientSocket);
            spdlog::debug("onDisconnect: ConnectionThread for incomming connection ended");
        };

        // Start thread for new connection
        std::future<void> future = std::async(&Mesh::connectionThread, this, incommingConnection, onDisconnect);
    });
}

void Mesh::start() {
    isRunning = true;

    // Start NodeManager thread
    nodeManagerThread = std::thread(&Mesh::nodeManager, this);

	// Start TCP server for incomming connections
	server->start();
}

void Mesh::stop() {
    // Stop TCP server and close all incomming connections
    std::cout << "Server stopping ..." << std::endl << std::flush;
    server->stop();
    std::cout << "Server stopped. " << std::endl << std::flush;

    std::cout << "Stoping mesh service ..." << std::endl << std::flush;
    isRunning = false;
    cv.notify_all();

    if (nodeManagerThread.joinable()) {
        nodeManagerThread.join();
    }

    std::cout << "Closing all connections ..." << std::endl << std::flush;
    // Close all outgoing connections
    for (auto& pair : outgoingConnections) {
        auto& connection = pair.second;
        if (connection) {
            connection->close();
        }
    }

    std::cout << "All threads stoped." << std::endl << std::flush;
}

void Mesh::connectionThread(std::shared_ptr<NodeConnection> connection, std::function<void()> onDisconnect) {
    pthread_setname_np(pthread_self(), "NodeConnection");
    const int socket = connection->getSocket();

    spdlog::trace("connectionThread: Connection thread started ...");

    // Wait for handshake from client or response from server
    if (connection->waitForHandshake() < 0) {
        spdlog::trace("connectionThread: Handshake unsuccessful!");

        if (onDisconnect) {
            onDisconnect();
        }

        connection->close();

        return;
    }

    spdlog::debug("connectionThread: Handshake complete");

    const std::array<uint8_t, 16> remoteNodeId = connection->getRemoteNodeId();
    std::stringstream ss;

    for (auto byte : remoteNodeId) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
    }

    std::string hexRemoteNodeId = ss.str();
    spdlog::info("Node {} connected", hexRemoteNodeId);

    char buffer[1024];
    ssize_t bytes_received;
    while ((bytes_received = recv(socket, buffer, sizeof(buffer), 0)) > 0) {

        PrintBuffer(buffer, bytes_received, 16);
        // 1. Decode header if buffer is larger that header size
        // 2. Wait for buffer to be size of packetSize
        // 3. Validate CRC16
        // 4. If CRC is valid call on_data_received callback

        std::string data(buffer, bytes_received);
        //on_data_received(client, data);
    }

    spdlog::info("Node {} disconnected", hexRemoteNodeId);
    if (onDisconnect) {
        onDisconnect();
    }

    connection->close();
    spdlog::trace("Connection thread is stoping ...");
}

void Mesh::nodeManager() {
    spdlog::debug("nodeManager: Starting NodeManager thread ...");
    pthread_setname_np(pthread_self(), "NodeManager");

    //const uint32_t softLimit = 2;
    const uint32_t hardLimit = 3;

    // 1. Nawiązać wstępną pulę połączeń (maksymalna dopuszczona ilość połączeń roboczych)
    // 2. Sprawdzić jakość połączeń, chęć połączenia ze strony zdalnego hosta i czy w ogóle się udało
    // 3. Zredukować ilość połączeń do optimum sieci zamykając najgorsze połączenia
    // 4. Jeśli są, wypróbować inne połączenia z listy nawiązując maksymalną dopuszczoną ilość połączeń roboczych i skoczyć do pkt. 2
    // 5. Monitorować aktywne pozostałe połączenia, jeśli któreś zostanie zamkniętę, skocz do pkt. 1

    while (isRunning) {
        // Step 1. Select new nodes to connect
        for (auto& nodeAddress: nodeAddressList) {
            // Don't connect new nodes if hard limit is reached
            if (this->outgoingConnections.size() >= hardLimit) {
                break;
            }

            if (nodeAddress.newOnList) {
                // Skip nodes already connected to us
                // if (server->isConnected(nodeAddress.address)) {
                //     std::cout << "Node " << nodeAddress.address << " already connected to us." << std::endl;
                //     continue;
                // }

                // Skip nodes that we already are connected
                // if (connectedAddresses.count(nodeAddress.address)) {
                //     std::cout << "We are already connected to " << nodeAddress.address << "." << std::endl;
                //     continue;
                // }

                if (IpTools::isLocalNetworkAddress(nodeAddress.address)) {
                    spdlog::debug("nodeManager: Connecting to local node: {}:{}", nodeAddress.address, nodeAddress.port);
                    connectToNode(nodeAddress.address, 8420);
                } else {
                    spdlog::debug("nodeManager: Connecting to global node: {}:{}", nodeAddress.address, nodeAddress.port);
                    connectToNode(nodeAddress.address, 8420);
                }

                // TODO: Dodać mutex przy zapisie
                nodeAddress.newOnList = false;
            }
        }
        // Sprawdzam, czy są nietestowane jeszcze połączenia, jeśli tak, i limit nie został osiągnięty, to nawiązuje połączenie

        // Jeśli są nawiązane połączenia, i nie mają przetestowanej jakości - testujemy ich jakość

        // Jeśli istnieje ilość połączeń z przetestowaną jakością, powyżej softLimit, zamykamy najgorsze (inaczej pomijamy ten krok)

        // We break the main loop if running flag is set to false
        std::unique_lock<std::mutex> lk(cv_m);
        if(cv.wait_for(lk, std::chrono::milliseconds(100), [&]{return !isRunning;})) {
            break;
        }
    }

    // std::cout << "Closing connections ..." << std::endl << std::flush;
    // TODO: Zamknąć wszystkie nawiązane połączenia ...

    spdlog::debug("nodeManager: Stopping NodeManager thread ...");
}

void Mesh::addNode(const std::string& address, const uint16_t port) {
    NodeAddress nodeAddress = {
        address,
        port,
        true
    };

    std::lock_guard<std::mutex> lock(nodeAddressListMutex);
    nodeAddressList.push_back(nodeAddress);
}

void Mesh::onNodeConnected(const std::string &nodeId) {
    std::cout << "New mesh node connected: " << nodeId << std::endl;

    //sendDataTo(nodeId, "example-foo", "Lorem ipsum, fucking working");
}

void Mesh::onNodeDisconnected(const std::string &nodeId) {
    std::cout << "New mesh node disconnected: " << nodeId << std::endl;
}

void Mesh::onDataReceived(const std::string& nodeId, const std::string& dataName, const std::string& message) {
	std::cout << "Data received from node: " << nodeId << ", data name: " << dataName << ", data: " << message << std::endl;
}

void Mesh::connectToNode(const std::string& address, const int port) {
    std::shared_ptr<TcpClient> client = std::make_shared<TcpClient>();

    client->onConnect([this, client, address, port](int clientSocket) {
        const invilite::ClientId* nodeId = this->nodeId;
        std::shared_ptr<NodeConnection> outgoingConnection = std::make_shared<NodeConnection>(clientSocket, nodeId, this->networkSecret);

        {
            std::lock_guard<std::mutex> lock(this->outgoingConnectionsMutex);
            this->outgoingConnections[clientSocket] = outgoingConnection;
        }

        auto onDisconnect = [this, clientSocket]() {
            std::lock_guard<std::mutex> lock(this->outgoingConnectionsMutex);
            this->outgoingConnections.erase(clientSocket);
            spdlog::debug("onDisconnect: ConnectionThread for outgoing connection ended");
        };

        std::future<void> future = std::async(&Mesh::connectionThread, this, outgoingConnection, onDisconnect);

        // Send handshake
        int handshakeResult = outgoingConnection->initHandshake();
        if (handshakeResult != 0) {
            std::cout << "Unable to send handshake!" << std::endl;
            outgoingConnection->close();
        }

        spdlog::trace("connectToNode: Handshake to {}:{} send successfuly.", address, port);
    });

    spdlog::trace("connectToNode: Opening connection to {}:{} ...", address, port);

    // Start connection
    client->connect(address, port);

    // Define simple data receive function, to handle only "node id" packets
    // client->onDataReceived([this, client, address](const std::string& data) {
    //     auto packetHeader = Serializer::getHeader(data);
    //     if (packetHeader == MeshPacket::NODE_ID_PACKET) {
    //         NodeIdPacket nodeIdPacket = NodeIdPacket::unpack(data);
    //         const std::string nodeId = nodeIdPacket.nodeId;

    //         // Detect loop connection
    //         if (nodeId == *this->nodeId) {
    //             std::cout << "Loop connection detected, disconnecting!" << std::endl;
    //             client->disconnect();
    //         }

    //         {
    //             // Register outgoing connection
    //             std::lock_guard<std::mutex> lockOutgoingNodes(nodes_mutex_);
    //             outgoing_nodes_[nodeId] = client;
    //         }

    //         client->onDisconnect([this, nodeId, address]() {
    //             std::lock_guard<std::mutex> lockOutgoingNodes(nodes_mutex_);
    //             std::lock_guard<std::mutex> lockconnectedAddresses(connectedAddressesMutex);
    //             outgoing_nodes_.erase(nodeId);
    //             this->connectedAddresses.erase(address);
                
    //             onNodeDisconnected(address);
    //         });

    //         onNodeConnected(nodeId);

    //         // Redefine data receive function, to handle all protocol communications
    //         client->onDataReceived([this, nodeId](const std::string& data) {
    //             auto packetHeader = Serializer::getHeader(data);
    //             switch(packetHeader) {
    //             case MeshPacket::NAMED_STRING_PACKET:
    //                 NamedStringPacket namedStringPacket = NamedStringPacket::unpack(data);
    //                 onDataReceived(nodeId, namedStringPacket.dataName, namedStringPacket.data);
    //                 break;
    //             }
    //         });
    //     }
    // });
}
