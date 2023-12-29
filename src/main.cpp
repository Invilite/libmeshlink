#include <uv.h>     // libuv1-dev
#include <cli.h>
#include <thread>
#include <memory>
#include <csignal>
#include <cstring>
#include <iostream>
#include <unistd.h> // usleep
#include <spdlog/spdlog.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/fmt/fmt.h>
#include "Mesh.h"
#include "ClientId.h"
#include "Serializer.h"
#include "NetDiscovery.h"
#include "IpTools.h"
//#include "Graph.h"

const std::string serviceName = "meshlinkd";
const std::string cachePath = "/var/cache/" + serviceName;
const std::string runDataPath = "/run/" + serviceName;

static std::atomic<bool> exitServer(false);
static void signalHandler(int signum);
static invilite::ClientId clientId(cachePath + "/node_id");
static invilite::NodeList nodeList(cachePath + "/node_list");
static const std::string nodeId = clientId.getId();
static invilite::Mesh mesh(&nodeId);

NetDiscovery discovery(8420);

int main(int argc, char** argv) {
    //spdlog::info("Meshlinkd P2P Information Exchange Service");
    CLI::App app{"Meshlinkd P2P Information Exchange Service"};
    //std::string filename;
    //app.add_option("-f,--file", filename, "File name")->required();

    bool showGraph = false;
    bool daemon = false;
    app.add_flag("-g,--graph", showGraph, "Show connection graph");
    app.add_flag("-d,--daemon", daemon, "Run as daemon");

    CLI11_PARSE(app, argc, argv);

    // Register signals handler
    signal(SIGINT, signalHandler);
    signal(SIGTERM, signalHandler);

    // Get local network interfaces and addresses
    std::vector<invilite::NetworkInterface> interfacesList;
    invilite::IpTools::getLocalInterfaces(&interfacesList);

    // Load known node addresses from cache file
    const std::set<std::string>& allEntries = nodeList.getAll();
    for (const std::string& address: allEntries) {
        mesh.addNode(address, 8420);
    }

    // Discover other nodes in local network
	discovery.onDiscover([&interfacesList](const std::string &address) {
        if (!invilite::IpTools::isLocalAddress(&interfacesList, address)) {
            if (nodeList.add(address)) {
                std::cout << "New node discovered in network [" << address << "]" << std::endl;
                mesh.addNode(address, 8420);
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
        while(!exitServer.load(std::memory_order_relaxed)) {
            usleep(100000); // Sleep na 100ms
        }
    }    

    try {
        discovery.stopListening();
    } catch (const std::exception &e) {
        std::cerr << "Exception caught when stopping discovery service: " << e.what() << std::endl;
    }

    try {
        std::cout << "Stopping mesh ..." << std::endl;
        mesh.stop();
    } catch (const std::exception &e) {
        std::cerr << "Exception caught when stopping mesh service: " << e.what() << std::endl;
    }

    std::cout << "Exiting ..." << std::endl;

    return 0;
}

void signalHandler(int signum) {
    std::cout << "Otrzymano sygnał: " << signum << std::endl;

    if (signum == 15) {         // SIGTERM
        exitServer.store(true, std::memory_order_relaxed);
    } else if (signum == 2) {   // SIGINT
        exitServer.store(true, std::memory_order_relaxed);
    }

    // Przywróć domyślną obsługę sygnału i wysyłanie sygnału do procesu
    //signal(signum, SIG_DFL);
    //raise(signum);
}
