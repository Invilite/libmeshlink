#ifndef MESH_H
#define MESH_H

#include <mutex>
#include <vector>
#include <thread>
#include <shared_mutex>
#include <condition_variable>
#include <cryptopp/secblock.h>
#include "debug.h"
#include "NodeId.h"
#include "IpTools.h"
#include "NodeList.h"
#include "MeshEvent.h"
#include "TcpClient.h"
#include "TcpServer.h"
#include "SimpleHash.h"
#include "PacketObserver.h"
#include "NodeConnection.h"

enum NodeListStatus {
	UNKNOWN,
};

struct NodeAddress {
	NodeListStatus status;
    std::string address;
    uint16_t port;
    bool newOnList;
};

namespace invilite {
	class Mesh {
	public:
		using OnReceiveType = std::function<void(const MeshEvent*, const std::array<uint8_t, 16>*)>;

		Mesh(const uint16_t port, const invilite::NodeId* nodeId, const std::vector<uint32_t> networkSecretKey);
		virtual ~Mesh() = default;
		void start();
		void stop();
		void attach(PacketObserver* observer);
		void detach(PacketObserver* observer);
		void setOnReceivedCallback(OnReceiveType callback);

    	void addNode(const std::string& address, const uint16_t port);

    	// Broadcast data to all connected nodes
    	void broadcast(const std::vector<uint8_t>* data);

    	// Send data to one connected node
    	void send(const std::vector<uint8_t>* data, const std::array<uint8_t, 16>* nodeId = NULL);

	protected:
		const std::shared_ptr<invilite::TcpServer> server;

		// Nodes map after successful handshake
		std::shared_mutex connectionsMutex;
		std::unordered_map<std::array<uint8_t, 16>, std::shared_ptr<NodeConnection>, SimpleHash> connections;

		// Active connections (incomming)
		std::shared_mutex incommingConnectionsMutex;
	    std::unordered_map<int, std::shared_ptr<NodeConnection>> incommingConnections;

	    // Active connections (outgoing)
	    std::shared_mutex outgoingConnectionsMutex;
	    std::unordered_map<int, std::shared_ptr<NodeConnection>> outgoingConnections;

	    // List of all known nodes adresses
		std::mutex newAddressBufferMutex;
		std::list<NodeAddress> newAddressBuffer;
		std::list<NodeAddress> nodeAddressList;

		virtual void nodeManager();
		void connectionThread(std::shared_ptr<NodeConnection> connection, std::function<void()> onDisconnect, std::function<void()> onHandshake);

		// Connect to other server, send clientId, and wait for response with server client id, add new item to out_clients
    	void connect(const std::string& address, const int port);

    	// Send event to all observers
    	void notify(const std::vector<uint8_t>* data, const std::array<uint8_t, 16>* remoteNodeId);

	private:
		const invilite::NodeId* nodeId;
		SecByteBlock networkSecret;
		std::thread nodeManagerThread;
		std::condition_variable cv;
		std::mutex cv_m;
		std::atomic<bool> isRunning = false;
		std::list<PacketObserver*> observers;
		OnReceiveType onReceive;
	};
}


#endif // MESH_H