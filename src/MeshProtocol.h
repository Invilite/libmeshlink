#ifndef MESH_PROTOCOL_H
#define MESH_PROTOCOL_H

#include <memory>
#include <unordered_map>
#include "NodeList.h"
#include "TcpClient.h"
#include "TcpServer.h"
#include "Serializer.h"
#include "ClientHandler.h"

namespace invilite {

enum MeshPacket {
    NODE_ID_PACKET = 0x01,
    NAMED_STRING_PACKET = 0x10
};

struct NodeIdPacket {
    const std::string nodeId;

    // Dodaj konstruktor, który inicjalizuje stałe pole nodeId
    explicit NodeIdPacket(const std::string& nodeId) : nodeId(nodeId) {}

    std::string pack() {
        invilite::Serializer serializer;
        serializer.start_map(MeshPacket::NODE_ID_PACKET, 1);
        serializer.pack("nodeId", nodeId);

        return serializer.str();
    }

    static NodeIdPacket unpack(const std::string& data) {
        auto map = invilite::Serializer::unpack(data);
        std::string unpackedNodeId = std::get<std::string>(map["nodeId"]);

        return NodeIdPacket(unpackedNodeId);
    }
};

struct NamedStringPacket {
    const std::string dataName;
    const std::string data;

    explicit NamedStringPacket(const std::string& dataName, const std::string& data) : dataName(dataName), data(data) {}

    std::string pack() {
        invilite::Serializer serializer;
        serializer.start_map(MeshPacket::NAMED_STRING_PACKET, 2);
        serializer.pack("dataName", dataName);
        serializer.pack("data", data);

        return serializer.str();
    }

    static NamedStringPacket unpack(const std::string& data) {
        auto map = invilite::Serializer::unpack(data);
        std::string unpackedDataName = std::get<std::string>(map["nodeId"]);
        std::string unpackedData = std::get<std::string>(map["nodeId"]);

        return NamedStringPacket(unpackedDataName, unpackedData);
    }
};

class MeshProtocol {
public:
    MeshProtocol(const std::string* nodeId);
    //virtual ~MeshProtocol() = default;

    // On every new connection, wait for clienId and send own in response, add new item to in_clients
    void startServer(const int port);
    void stopServer();

protected:
    // virtual void processData(const std::string& clientId, const std::string& dataName, void* data, uint32_t dataLen) = 0;

    // Call this after in or out connection connect
    virtual void onNodeConnected(const std::string& nodeId) = 0;

    // Call this after in or out connection disconnect
    virtual void onNodeDisconnected(const std::string& nodeId) = 0;

    // Basic function for requesting data from other node
    void requestDataFrom(const std::string& nodeId, const std::string& dataName);

    // Call this after we received request for sending data from other node
    void onDataRequest(std::function<void(const std::string& nodeId, const std::string& dataName)> onDataRequest);

    // Function for sending data to other node
    void sendDataTo(const std::string& nodeId, const std::string& dataName, const std::string& data);

    // Call this after we received new data from other node
    virtual void onDataReceived(const std::string& nodeId, const std::string& dataName, const std::string& message) = 0;

    // Basic function for responding for request or just sending data
    template <typename T> void sendDataTo(std::shared_ptr<TcpClient> client, T& packet);
    template <typename T> void sendDataTo(const std::string& nodeId, T& packet);

    // Return true if node is connected to server or as outgoing tcp connection
    // TODO: Implement
    bool isNodeConnected(const std::string& nodeId);

    // Server methods
    void onConnect(const std::shared_ptr<invilite::ClientHandler> &client);
    void onDisconnect(const std::shared_ptr<invilite::ClientHandler> &client);
    void onServerDataReceived(const std::shared_ptr<invilite::ClientHandler> &client, const std::string &data);

protected:
    // List of IP addresses of connected clients
    // TODO: Add isClientConnected method
    std::set<std::string> connectedAddresses;

private:
    const std::string* nodeId;

    std::mutex nodes_mutex_;

    std::mutex connectedAddressesMutex;

    // Map clientId with TcpClients for outgoing connections
    std::unordered_map<std::string, std::shared_ptr<TcpClient>> outgoing_nodes_;

    // Map clientId with ClientHandler for incomming connections
    std::unordered_map<std::string, std::shared_ptr<invilite::ClientHandler>> incomming_nodes_;
};

} // namespace invilite

#endif // MESH_PROTOCOL_H