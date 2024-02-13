#ifndef MESH_H
#define MESH_H

#include <list>
#include <thread>
#include <future>
#include <cstring>
#include <iostream>
#include <condition_variable>
#include <cryptopp/secblock.h>
#include "IpTools.h"
#include "NodeList.h"
#include "ClientId.h"
#include "TcpServer.h"
#include "TcpClient.h"
#include "NodeConnection.h"

struct NodeAddress {
    std::string address;
    uint16_t port;
    bool newOnList;
};

namespace invilite {
	class Mesh {
	public:
		Mesh(const uint16_t port, const invilite::ClientId* nodeId, const std::vector<uint32_t> networkSecretKey);
		virtual ~Mesh() = default;
		void start();
		void stop();

    	void onNodeConnected(const std::string &nodeId);
    	void onNodeDisconnected(const std::string &nodeId);
    	void onDataReceived(const std::string& nodeId, const std::string& dataName, const std::string& message);

    	// TODO: Implement this
    	void addNode(const std::string& address, const uint16_t port);

	protected:
		const std::shared_ptr<invilite::TcpServer> server;
		// Nodes after successful handshake
		// std::mutex connectionsMutex;
		// std::unordered_map<int, std::shared_ptr<NodeConnection>> connections;

		// Connections threads
		std::vector<std::thread> threads;

		// Active connections (incomming)
		std::mutex incommingConnectionsMutex;
	    std::unordered_map<int, std::shared_ptr<NodeConnection>> incommingConnections;

	    // Active connections (outgoing)
	    std::mutex outgoingConnectionsMutex;
	    std::unordered_map<int, std::shared_ptr<NodeConnection>> outgoingConnections;

		std::thread nodeManagerThread;
		std::list<NodeAddress> nodeAddressList;

		void nodeManager();
		void connectionThread(std::shared_ptr<NodeConnection> connection, std::function<void()> onDisconnect);

		// Connect to other server, send clientId, and wait for response with server client id, add new item to out_clients
    	void connectToNode(const std::string& address, const int port);

	private:
		const invilite::ClientId* nodeId;
		SecByteBlock networkSecret;
		std::mutex nodeAddressListMutex;
		std::condition_variable cv;
		std::mutex cv_m;
		std::atomic<bool> isRunning = false;
	};
}


#endif // MESH_H