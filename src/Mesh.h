#ifndef MESH_H
#define MESH_H

#include <list>
#include <thread>
#include <cstring>
#include <iostream>
#include <condition_variable>
#include "TcpServer.h"
#include "TcpClient.h"
#include "IpTools.h"
#include "NodeList.h"
#include "ClientId.h"
#include "MeshProtocol.h"

struct NodeAddress {
    std::string address;
    uint16_t port;
    bool newOnList;
};

namespace invilite {
	class Mesh: public MeshProtocol {
	public:
		Mesh(const std::string* nodeId);
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
		std::vector<std::shared_ptr<TcpClient>> clients;
		std::thread serverThread;

		std::thread nodeManagerThread;
		std::list<NodeAddress> nodeAddressList;

		void nodeManager();

	private:
		std::mutex nodeAddressListMutex;
		std::condition_variable cv;
		std::mutex cv_m;
		std::shared_ptr<invilite::TcpClient> getLongestConnectedClient();
		std::atomic<bool> isRunning = false;
	};
}


#endif // MESH_H