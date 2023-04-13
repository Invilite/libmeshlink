#include <iostream>
#include <cstring>
#include <thread>
#include <memory>
#include <uv.h>
#include <csignal>
#include <unistd.h> // usleep
#include "Mesh.h"
#include "ClientId.h"
#include "Serializer.h"
#include "NetDiscovery.h"
#include "IpTools.h"

const std::string serviceName = "meshlinkd";
const std::string cachePath = "/var/cache/" + serviceName;
const std::string runDataPath = "/run/" + serviceName;

static bool exitServer = false;
static void signalHandler(int signum);
static invilite::ClientId clientId(cachePath + "/node_id");
static invilite::NodeList nodeList(cachePath + "/node_list");
static const std::string nodeId = clientId.getId();
static invilite::Mesh mesh(&nodeId, &nodeList);

NetDiscovery discovery(8420);

int main() {
    // Register signals handler
    signal(SIGINT, signalHandler);
    signal(SIGTERM, signalHandler);

    // Get local network interfaces and addresses
    std::vector<invilite::NetworkInterface> interfacesList;
    invilite::IpTools::getLocalInterfaces(&interfacesList);

    // Discover other nodes in local network
	discovery.onDiscover([&interfacesList](const std::string &address) {
        if (!invilite::IpTools::isLocalAddress(&interfacesList, address)) {
            if (nodeList.add(address)) {
                std::cout << "New node discovered in network [" << address << "]" << std::endl;
            }
        }
    });
	discovery.startListening();

    usleep(100000); // Sleep na 100ms
    discovery.discovery();
    usleep(1000000); // Sleep na 1000ms

    // Starting mesh network ...
	std::cout << "Starting mesh network with local id \"" << nodeId << "\" ..." << std::endl;
    mesh.start();

    while(!exitServer) {
    	usleep(100000); // Sleep na 100ms
    }

    std::cout << "Exiting ..." << std::endl;

    discovery.stopListening();
    mesh.stop();

    return 0;
}

void signalHandler(int signum) {
    std::cout << "Otrzymano sygnał: " << signum << std::endl;

    if (signum == 15) {         // SIGTERM
        exitServer = true;
    } else if (signum == 2) {   // SIGINT
        exitServer = true;
    }

    // Przywróć domyślną obsługę sygnału i wysyłanie sygnału do procesu
    signal(signum, SIG_DFL);
    raise(signum);
}
