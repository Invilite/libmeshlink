#ifndef MESH_H
#define MESH_H

#include <set>
#include <list>
#include <mutex>
#include <string>
#include <vector>
#include <chrono>
#include <thread>
#include <cstring>
#include <iostream>
#include <unistd.h> // usleep
#include <algorithm>
#include <condition_variable>
#include <cryptopp/secblock.h>
#include "NodeId.h"
#include "IpTools.h"
#include "NodeList.h"
#include "TcpClient.h"
#include "TcpServer.h"
#include "NodeConnection.h"

struct NodeAddress {
    std::string address;
    uint16_t port;
    bool newOnList;
};

namespace invilite {
	class Mesh {
	public:
		Mesh(const uint16_t port, const invilite::NodeId* nodeId, const std::vector<uint32_t> networkSecretKey);
		virtual ~Mesh() = default;
		void start();
		void stop();

    	// TODO: Implement this
    	void addNode(const std::string& address, const uint16_t port);

	protected:
		const std::shared_ptr<invilite::TcpServer> server;

		// Nodes after successful handshake
		std::mutex connectionsMutex;
		std::unordered_map<int, std::shared_ptr<NodeConnection>> connections;

		// Active connections (incomming)
		std::mutex incommingConnectionsMutex;
	    std::unordered_map<int, std::shared_ptr<NodeConnection>> incommingConnections;

	    // Active connections (outgoing)
	    std::mutex outgoingConnectionsMutex;
	    std::unordered_map<int, std::shared_ptr<NodeConnection>> outgoingConnections;

		std::thread nodeManagerThread;
		std::list<NodeAddress> nodeAddressList;

		virtual void nodeManager();
		void connectionThread(std::shared_ptr<NodeConnection> connection, std::function<void()> onDisconnect);

		// Connect to other server, send clientId, and wait for response with server client id, add new item to out_clients
    	void connect(const std::string& address, const int port);

    	void onDataReceived(const std::vector<uint8_t>*data);

	private:
		const invilite::NodeId* nodeId;
		SecByteBlock networkSecret;
		std::mutex nodeAddressListMutex;
		std::condition_variable cv;
		std::mutex cv_m;
		std::atomic<bool> isRunning = false;
	};
}


#endif // MESH_H