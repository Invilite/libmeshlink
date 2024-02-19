#include "Mesh.h"

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
            std::unique_lock<std::shared_mutex> lock(this->incommingConnectionsMutex);
            this->incommingConnections[clientSocket] = incommingConnection;
        }

        // Remove connection from map on disconnect
        auto onDisconnect = [this, clientSocket, incommingConnection]() {
            {
                const std::array<uint8_t, 16> remoteNodeId = incommingConnection->getRemoteNodeId();
                std::unique_lock<std::shared_mutex> lock(this->connectionsMutex);
                this->connections.erase(remoteNodeId);
            }

            {
                std::unique_lock<std::shared_mutex> lock(this->incommingConnectionsMutex);
                this->incommingConnections.erase(clientSocket);
            }

            incommingConnection->close();
        };

        auto onHandshake = [this, clientSocket, incommingConnection]() {
            const std::array<uint8_t, 16> remoteNodeId = incommingConnection->getRemoteNodeId();

            {
                // Add connection to map of sucessful connections
                std::unique_lock<std::shared_mutex> lock(this->connectionsMutex);
                this->connections[remoteNodeId] = incommingConnection;
            }
        };

        // Start thread for new connection
        std::thread(&Mesh::connectionThread, this, incommingConnection, onDisconnect, onHandshake).detach();
    });
}

void Mesh::connect(const std::string& address, const int port) {
    std::shared_ptr<TcpClient> client = std::make_shared<TcpClient>();

    // TODO: client
    client->onConnect([this, client, address, port](int clientSocket, const sockaddr_storage* clientAddress) {
        std::shared_ptr<NodeConnection> outgoingConnection = std::make_shared<NodeConnection>(clientSocket, clientAddress, this->nodeId, this->networkSecret);
        spdlog::trace("[{}] Connected.", outgoingConnection->getRemoteClientAddress());

        {
            // Add outgoing connection to map of outgoing connections
            std::unique_lock<std::shared_mutex> lock(this->outgoingConnectionsMutex);
            this->outgoingConnections[clientSocket] = outgoingConnection;
        }

        auto onDisconnect = [this, clientSocket, outgoingConnection]() {
            {
                const std::array<uint8_t, 16> remoteNodeId = outgoingConnection->getRemoteNodeId();
                std::unique_lock<std::shared_mutex> lock(this->connectionsMutex);
                this->connections.erase(remoteNodeId);
            }

            {
                std::unique_lock<std::shared_mutex> lock(this->outgoingConnectionsMutex);
                this->outgoingConnections.erase(clientSocket);
            }

            outgoingConnection->close();
            spdlog::debug("onDisconnect: ConnectionThread for outgoing connection ended");
        };

        auto onHandshake = [this, clientSocket, outgoingConnection]() {
            const std::array<uint8_t, 16> remoteNodeId = outgoingConnection->getRemoteNodeId();

            {
                // Add connection to map of sucessful connections
                std::unique_lock<std::shared_mutex> lock(this->connectionsMutex);
                this->connections[remoteNodeId] = outgoingConnection;
            }

            std::vector<uint8_t> data;
            data.reserve(4);
            data.push_back(0x01);
            data.push_back(0x02);
            data.push_back(0x03);
            data.push_back(0x04);

            const std::vector<uint8_t> encData = outgoingConnection->encryptData(data);
            const char* buffer = reinterpret_cast<const char*>(encData.data());
            PrintBuffer(buffer, encData.size(), 24);
            outgoingConnection->sendRaw(encData);
        };

        // Start thread for new connection
        std::thread(&Mesh::connectionThread, this, outgoingConnection, onDisconnect, onHandshake).detach();

        // Init handshake with server
        int handshakeResult = outgoingConnection->initHandshake();
        if (handshakeResult != 0) {
            spdlog::trace("[{}] Unable to send handshake!", outgoingConnection->getRemoteClientAddress());
            outgoingConnection->close();
        } else {
            spdlog::trace("[{}] Handshake sended successfuly.", outgoingConnection->getRemoteClientAddress());
        }
    });

    // Start connection
    spdlog::debug("Opening new connection to {} ...", address);
    client->connect(address, port);
}

void Mesh::start() {
    this->isRunning = true;

    // Start NodeManager thread
    nodeManagerThread = std::thread(&Mesh::nodeManager, this);

	// Start TCP server for incomming connections
	if (server->start() == 0) {
        spdlog::debug("Server listening ...");
    }
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
            std::shared_lock<std::shared_mutex> incommingLock(this->incommingConnectionsMutex);
            std::shared_lock<std::shared_mutex> outgoingLock(this->outgoingConnectionsMutex);
            allClosed = incommingConnections.empty() && outgoingConnections.empty();
        }

        if (!allClosed) {
            // Czekaj 50ms przed kolejnym sprawdzeniem
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
    }

    std::cout << "Mesh network stopped." << std::endl << std::flush;
}

void Mesh::attach(PacketObserver* observer) {
    observers.push_back(observer);
}

void Mesh::detach(PacketObserver* observer) {
    observers.remove(observer);
}

void Mesh::setOnReceivedCallback(OnReceiveType callback) {
    this->onReceive = callback;
}

void Mesh::notify(const std::vector<uint8_t>* data, const std::array<uint8_t, 16>* remoteNodeId) {
    for (PacketObserver* observer : observers) {
        observer->update(data, remoteNodeId);
    }
}

void Mesh::broadcast(const std::vector<uint8_t>* data) {
    // TODO: Made this async?
    std::shared_lock<std::shared_mutex> lock(this->connectionsMutex);
    for (const auto& pair: connections) {
        //std::cout << "Klucz: " << pair.first << std::endl;
        const std::vector<uint8_t> encData = pair.second->encryptData(*data);
        pair.second->sendRaw(encData);
    }
}

void Mesh::send(const std::vector<uint8_t>* data, const std::array<uint8_t, 16>* nodeId) {
    auto it = connections.find(*nodeId);
    if (it != connections.end()) {
        auto connection = it->second;
        const std::vector<uint8_t> encData = connection->encryptData(*data);
        connection->sendRaw(encData);
    }
}

void Mesh::connectionThread(std::shared_ptr<NodeConnection> connection, std::function<void()> onDisconnect, std::function<void()> onHandshake) {
    pthread_setname_np(pthread_self(), "NodeConnection");
    const int socket = connection->getSocket();
    spdlog::trace("[{}] Connection thread started", connection->getRemoteClientAddress());

    // Wait for handshake from client or response from server
    if (connection->waitForHandshake() < 0) {
        if (onDisconnect) {
            onDisconnect();
        }
        spdlog::trace("[{}] Handshake unsuccessful", connection->getRemoteClientAddress());
        return;
    }

    const std::array<uint8_t, 16> remoteNodeId = connection->getRemoteNodeId();
    {
        std::stringstream ss;
        for (auto byte: remoteNodeId) ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
        std::string nodeIdAsHexString = ss.str();
        spdlog::trace("[{}] Handshake complete (node {})", connection->getRemoteClientAddress(), nodeIdAsHexString);
    }

    if (onHandshake) {
        onHandshake();
    }

    std::vector<uint8_t> packetBuffer;
    uint8_t  expectedProtocol = 0;
    uint32_t expectedPacketLength = 0;
    ssize_t  bytesReceived;
    char recvBuffer[8192];
    while ((bytesReceived = recv(socket, recvBuffer, sizeof(recvBuffer), 0)) > 0) {
        // std::cout << "New data received, " << bytesReceived << " bytes." << std::endl;
        // PrintBuffer(recvBuffer, bytesReceived, 24);
        packetBuffer.insert(packetBuffer.end(), recvBuffer, recvBuffer + bytesReceived);

        // Verify packet header if first 10 bytes was received
        if (expectedPacketLength == 0 && packetBuffer.size() >= 10) {
            if (!connection->verifyHeader(packetBuffer, expectedPacketLength, expectedProtocol)) {
                connection->close();
                spdlog::error("[{}] Wrong protocol header was received, connection terminated.", connection->getRemoteClientAddress());
            }
        }

        if (expectedPacketLength > 0 && packetBuffer.size() >= expectedPacketLength) {
            //std::cout << "Complete packet received." << std::endl;
            try {
                const std::vector<uint8_t>data = connection->decryptData(packetBuffer);
                if (onReceive) {
                    onReceive(&data, &remoteNodeId);
                }
                this->notify(&data, &remoteNodeId);
            } catch (const std::exception& e) {
                connection->close();
                spdlog::error("[{}] Unable to decrypt data: {}", connection->getRemoteClientAddress(), e.what());
            }

            packetBuffer.erase(packetBuffer.begin(), packetBuffer.begin() + expectedPacketLength);
            expectedPacketLength = 0;
        }
    }
    spdlog::trace("[{}] Connection closed", connection->getRemoteClientAddress());

    if (onDisconnect) {
        onDisconnect();
    }

    spdlog::trace("[{}] Connection thread ended", connection->getRemoteClientAddress());
}

void Mesh::nodeManager() {
    spdlog::debug("Starting NodeManager thread ...");
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
                    spdlog::debug("Connecting to local node: {}:{}", nodeAddress.address, nodeAddress.port);
                    connect(nodeAddress.address, 8420);
                } else {
                    spdlog::debug("Connecting to global node: {}:{}", nodeAddress.address, nodeAddress.port);
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

    spdlog::debug("Stopping NodeManager thread ...");
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
