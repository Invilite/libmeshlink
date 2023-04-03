#ifndef MESH_H
#define MESH_H

#include <thread>
#include <cstring>
#include <iostream>
#include "TcpServer.h"
#include "TcpClient.h"
#include "NodeList.h"

namespace invilite {
	class Mesh {
	public:
		Mesh(NodeList* nodeList_);
		void connect();
		void disconnect();

	protected:
		const std::shared_ptr<invilite::TcpServer> server;
		std::vector<std::shared_ptr<TcpClient>> clients;
		std::thread serverThread;
		NodeList* nodeList;

	private:

	};
}


#endif // MESH_H