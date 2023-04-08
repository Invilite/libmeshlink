#ifndef MESH_H
#define MESH_H

#include <thread>
#include <cstring>
#include <iostream>
#include "TcpServer.h"
#include "TcpClient.h"
#include "NodeList.h"
#include "ClientId.h"
#include "MeshProtocol.h"

namespace invilite {
	class Mesh: public MeshProtocol {
	public:
		Mesh(const std::string* nodeId, NodeList* nodeList_);
		virtual ~Mesh() = default;
		void connect();
		void disconnect();

    	void onNodeConnected(const std::string &nodeId);
    	void onNodeDisconnected(const std::string &nodeId);
    	void onDataReceived(const std::string& nodeId, const std::string& dataName, const std::string& message);

    	// TODO: Implement this
    	void addNode(const std::string& address, const int port);

	protected:
		const std::shared_ptr<invilite::TcpServer> server;
		invilite::NodeList* nodeList;
		std::vector<std::shared_ptr<TcpClient>> clients;
		std::thread serverThread;

	private:
	};
}


#endif // MESH_H