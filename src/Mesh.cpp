#include "Mesh.h"
#include <iomanip> // Dla std::setw i std::setfill

using namespace invilite;
using std::make_shared;

Mesh::Mesh(const uint16_t port, const NodeId* nodeId, const std::vector<uint32_t> networkSecretKey): server(make_shared<TcpServer>(port)), nodeId(nodeId) {
    // Copy network secret to local SecByteBlock variable
    this->networkSecret.resize(networkSecretKey.size() * sizeof(uint32_t));
    std::memcpy(this->networkSecret.BytePtr(), networkSecretKey.data(), this->networkSecret.size());

	// Handle server incomming connections
	server->onConnect([this](int clientSocket, const sockaddr_storage* clientAddress) {
        std::shared_ptr<NodeConnection> incommingConnection = std::make_shared<NodeConnection>(clientSocket, clientAddress, this->nodeId, this->networkSecret);

        {
            // Add incomming connection to map of incomming connections
            std::lock_guard<std::mutex> lock(this->incommingConnectionsMutex);
            this->incommingConnections[clientSocket] = incommingConnection;
        }

        // Remove connection from map on disconnect
        auto onDisconnect = [this, clientSocket]() {
            std::lock_guard<std::mutex> lock(this->incommingConnectionsMutex);
            this->incommingConnections.erase(clientSocket);
            spdlog::debug("onDisconnect: ConnectionThread for incomming connection ended");
        };

        // Start thread for new connection
        std::thread(&Mesh::connectionThread, this, incommingConnection, onDisconnect).detach();
    });
}

void Mesh::connect(const std::string& address, const int port) {
    spdlog::trace("connectToNode: Start");
    std::shared_ptr<TcpClient> client = std::make_shared<TcpClient>();

    client->onConnect([this, address, port](int clientSocket, const sockaddr_storage* clientAddress) {
        spdlog::trace("connectToNode: onConnect start");
        std::shared_ptr<NodeConnection> outgoingConnection = std::make_shared<NodeConnection>(clientSocket, clientAddress, this->nodeId, this->networkSecret);

        {
            // Add outgoing connection to map of outgoing connections
            std::lock_guard<std::mutex> lock(this->outgoingConnectionsMutex);
            this->outgoingConnections[clientSocket] = outgoingConnection;
        }

        auto onDisconnect = [this, clientSocket]() {
            std::lock_guard<std::mutex> lock(this->outgoingConnectionsMutex);
            this->outgoingConnections.erase(clientSocket);
            spdlog::debug("onDisconnect: ConnectionThread for outgoing connection ended");
        };

        // Start thread for new connection
        std::thread(&Mesh::connectionThread, this, outgoingConnection, onDisconnect).detach();

        // Init handshake with server
        int handshakeResult = outgoingConnection->initHandshake();
        if (handshakeResult != 0) {
            std::cout << "Unable to send handshake!" << std::endl;
            outgoingConnection->close();
        }

        spdlog::trace("connectToNode: Handshake to {}:{} send successfuly.", address, port);
    });

    spdlog::trace("connectToNode: Opening connection to {}:{} ...", address, port);

    // Start connection
    spdlog::trace("connectToNode: connect start");
    client->connect(address, port);
    spdlog::trace("connectToNode: connect finish");
}

void Mesh::start() {
    this->isRunning = true;

    // Start NodeManager thread
    nodeManagerThread = std::thread(&Mesh::nodeManager, this);

	// Start TCP server for incomming connections
	server->start();
}

void Mesh::stop() {
    // Stop TCP server and close all incomming connections
    std::cout << "Server stopping ... " << std::endl << std::flush;
    server->stop();

    std::cout << "Node manager stopping ... " << std::endl << std::flush;
    {
        std::lock_guard lk(cv_m);
        this->isRunning = false;
    }
    cv.notify_all();

    if (nodeManagerThread.joinable()) {
        nodeManagerThread.join();
    }

    std::cout << "Closing all outgoing connections ... " << std::endl << std::flush;
    for (auto& pair : outgoingConnections) {
        auto& connection = pair.second;
        if (connection) {
            connection->close();
        }
    }

    std::cout << "Closing all incomming connections ... " << std::endl << std::flush;
    for (auto& pair : incommingConnections) {
        auto& connection = pair.second;
        if (connection) {
            connection->close();
        }
    }

    std::cout << "Waiting for all connections to close ... " << std::endl << std::flush;
    bool allClosed = false;
    while (!allClosed) {
        {
            std::lock_guard<std::mutex> incomingLock(incommingConnectionsMutex);
            std::lock_guard<std::mutex> outgoingLock(outgoingConnectionsMutex);
            allClosed = incommingConnections.empty() && outgoingConnections.empty();
        }

        if (!allClosed) {
            // Czekaj 100ms przed kolejnym sprawdzeniem
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    }

    std::cout << "Mesh network stopped." << std::endl << std::flush;
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

    {
        // Add connection to map of sucessful connections
        std::lock_guard<std::mutex> lock(this->connectionsMutex);
        this->connections[socket] = connection;
    }

    std::string hexRemoteNodeId = ss.str();
    spdlog::info("Node {} connected", hexRemoteNodeId);

    std::vector<uint8_t> packetBuffer;
    uint32_t expectedPacketLength = 0;
    ssize_t bytes_received;
    char buffer[1024];
    while ((bytes_received = recv(socket, buffer, sizeof(buffer), 0)) > 0) {
        packetBuffer.insert(packetBuffer.end(), buffer, buffer + bytes_received);

        if (expectedPacketLength == 0 && packetBuffer.size() >= sizeof(uint32_t)) {
            memcpy(&expectedPacketLength, packetBuffer.data(), sizeof(uint32_t));
        }

        if (expectedPacketLength > 0 && packetBuffer.size() >= expectedPacketLength) {
            std::vector<uint8_t> packet(packetBuffer.begin(), packetBuffer.begin() + expectedPacketLength);
            packetBuffer.erase(packetBuffer.begin(), packetBuffer.begin() + expectedPacketLength);
            expectedPacketLength = 0;

            try {
                const std::vector<uint8_t>data = connection->decryptData(packet);
                this->onDataReceived(&data);

            } catch (const std::exception& e) {
                std::cerr << "Wyjątek podczas deszyfrowania danych: " << e.what() << std::endl;
            }

        }
    }

    {
        std::lock_guard<std::mutex> lock(this->connectionsMutex);
        this->connections.erase(socket);
    }

    spdlog::info("Node {} disconnected", hexRemoteNodeId);
    if (onDisconnect) {
        onDisconnect();
    }

    connection->close();
    spdlog::trace("Connection thread is stoping ...");
}

void Mesh::onDataReceived(const std::vector<uint8_t>*data) {
    if (data != nullptr) {
        for (const auto& byte : *data) {
            std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte) << " ";
        }
        std::cout << std::dec << std::endl; // Powrót do wyświetlania w systemie dziesiętnym
    }
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

    while (this->isRunning) {
        // Step 1. Select new nodes to connect
        for (auto& nodeAddress: nodeAddressList) {
            // Don't connect new nodes if thread is requested to finish
            if (!this->isRunning) {
                break;
            }

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
                    connect(nodeAddress.address, 8420);
                } else {
                    spdlog::debug("nodeManager: Connecting to global node: {}:{}", nodeAddress.address, nodeAddress.port);
                    connect(nodeAddress.address, 8420);
                }

                // TODO: Dodać mutex przy zapisie
                nodeAddress.newOnList = false;
            }
        }
        // Sprawdzam, czy są nietestowane jeszcze połączenia, jeśli tak, i limit nie został osiągnięty, to nawiązuje połączenie

        // Jeśli są nawiązane połączenia, i nie mają przetestowanej jakości - testujemy ich jakość

        // Jeśli istnieje ilość połączeń z przetestowaną jakością, powyżej softLimit, zamykamy najgorsze (inaczej pomijamy ten krok)

        // We break the main loop if running flag is set to false
        {
            std::unique_lock<std::mutex> lock(cv_m);
            if(cv.wait_for(lock, std::chrono::milliseconds(100), [&]{return !this->isRunning;})) {
                break;
            }
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
