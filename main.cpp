#include <iostream>
#include <cstring>
#include <thread>
#include <memory>
#include <uv.h>
#include <unistd.h> // usleep
#include "Mesh.h"
#include "ClientId.h"
#include "Serializer.h"
#include "NetDiscovery.h"
#include "IpTools.h"

const std::string serviceName = "meshlinkd";
const std::string cachePath = "/var/cache/" + serviceName;
const std::string runDataPath = "/run/" + serviceName;

static invilite::ClientId clientId(cachePath + "/node_id");
static invilite::NodeList nodeList(cachePath + "/node_list");
static const std::string nodeId = clientId.getId();
static invilite::Mesh mesh(&nodeId, &nodeList);

NetDiscovery discovery(8420);

int main() {
    // Get local network interfaces and addresses
    std::vector<invilite::NetworkInterface> interfacesList;
    invilite::IpTools::getLocalInterfaces(&interfacesList);

    std::cout << "My nodeId: " << nodeId << std::endl;
	discovery.onDiscover([&interfacesList](const std::string &address) {
        if (!invilite::IpTools::isLocalAddress(&interfacesList, address)) {
            mesh.addNode(address, 8420);
        }
    });
	discovery.startListening();


    usleep(100000); // Sleep na 100ms
    discovery.discovery();

    usleep(1000000); // Sleep na 1000ms

    // Starting mesh network ...
	std::cout << "Starting mesh network ..." << std::endl;
    mesh.connect();

    while(true) {
    	usleep(10000); // Sleep na 10ms
    }

    discovery.stopListening();
    mesh.disconnect();

    return 0;
}
