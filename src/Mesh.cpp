#include <unistd.h> // usleep
#include <iostream>
#include <string>
#include <set>
#include <list>
#include <mutex>
#include <vector>
#include <chrono>
#include <algorithm>
#include <condition_variable>
#include "Mesh.h"

invilite::Mesh::Mesh(const std::string* nodeId): MeshProtocol(nodeId), server(std::make_shared<invilite::TcpServer>(8420)) {
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
    isRunning = true;

    // Start NodeManager thread
    nodeManagerThread = std::thread(&invilite::Mesh::nodeManager, this);

	// Start TCP server for incomming connections
	serverThread = std::thread(&invilite::TcpServer::start, server);
    pthread_setname_np(serverThread.native_handle(), "TcpServer");
}

void invilite::Mesh::stop() {
    std::cout << "Stoping mesh service ..." << std::endl << std::flush;
    isRunning = false;
    cv.notify_all();

    server->stop();

    if(nodeManagerThread.joinable()) {
        nodeManagerThread.join();
    }

    if(serverThread.joinable()) {
        serverThread.join();
    }

    std::cout << "All threads stoped." << std::endl << std::flush;
}

void invilite::Mesh::nodeManager() {
    std::cout << "Starting NodeManager thread ..." << std::endl << std::flush;
    pthread_setname_np(pthread_self(), "NodeManager");

    const uint32_t softLimit = 2;
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
            if (connectedAddresses.size() >= hardLimit) {
                break;
            }

            if (nodeAddress.newOnList) {
                // Skip nodes already connected to us
                if (server->isConnected(nodeAddress.address)) {
                    std::cout << "Node " << nodeAddress.address << " already connected to us." << std::endl;
                    continue;
                }

                // Skip nodes that we already are connected
                if (connectedAddresses.count(nodeAddress.address)) {
                    std::cout << "We are already connected to " << nodeAddress.address << "." << std::endl;
                    continue;
                }

                if (invilite::IpTools::isLocalNetworkAddress(nodeAddress.address)) {
                    std::cout << "Connecting to local node: " << nodeAddress.address << std::endl;
                    connectToNode(nodeAddress.address, 8420);
                } else {
                    std::cout << "Connecting to global node: " << nodeAddress.address << std::endl;
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
        if(cv.wait_for(lk, std::chrono::milliseconds(500), [&]{return !isRunning;})) {
            break;
        }
    }

    std::cout << "Closing connections ..." << std::endl << std::flush;
    // TODO: Zamknąć wszystkie nawiązane połączenia ...

    std::cout << "Stoping NodeManager thread ..." << std::endl << std::flush;
}

void invilite::Mesh::addNode(const std::string& address, const uint16_t port) {
    NodeAddress nodeAddress = {
        address,
        port,
        true
    };

    std::lock_guard<std::mutex> lock(nodeAddressListMutex);
    nodeAddressList.push_back(nodeAddress);
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
