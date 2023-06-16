#include <iostream>
#include <cstring>
#include <thread>
#include <memory>
#include <uv.h>     // libuv1-dev
#include <csignal>
#include <unistd.h> // usleep
#include "Mesh.h"
#include "ClientId.h"
#include "Serializer.h"
#include "NetDiscovery.h"
#include "IpTools.h"
//#include "Graph.h"
#include "cli.h"

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

int main(int argc, char** argv) {
    CLI::App app{"Meshlinkd P2P Information Exchange Service"};
    //std::string filename;
    //app.add_option("-f,--file", filename, "File name")->required();

    bool showGraph = false;
    app.add_flag("-g,--graph", showGraph, "Show connection graph");

    CLI11_PARSE(app, argc, argv);

    // Register signals handler
    //signal(SIGINT, signalHandler);
    //signal(SIGTERM, signalHandler);

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

    // Starting mesh network ...
	std::cout << "Starting mesh network with local id \"" << nodeId << "\" ..." << std::endl;
    mesh.start();

    usleep(100000); // Sleep na 100ms
    // Discovery service should broadcast periodically only when there is no connection to any peer,
    // after connecting to any other node, node list will be downloaded
    discovery.discovery();
    usleep(1000000); // Sleep na 1000ms

    if (showGraph) {
        // sf::RenderWindow window(sf::VideoMode(1024, 768), "Nodes and Connections");
        // window.clear(sf::Color::Black);

        // sf::Font font;
        // if (!font.loadFromFile("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf")) {
        //     return -1;
        // }

        // Graph graph(font, window.getSize());
        // graph.addNode("abc1", {"def2", "ghi3"});
        // graph.addNode("def2", {"ghi3"});
        // graph.addNode("ghi3", {});

        // while (window.isOpen()) {
        //     sf::Event event;
        //     while (window.pollEvent(event)) {
        //         if (event.type == sf::Event::Closed) {
        //             window.close();
        //         }
        //     }

        //     window.clear(sf::Color::Black);
        //     graph.draw(window);
        //     window.display();
        // }    
    } else {
        while(!exitServer) {
            usleep(100000); // Sleep na 100ms
        }
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
