#include <cli.h>
#include <thread>
#include <memory>
#include <csignal>
#include <cstring>
#include <mqueue.h>
#include <iostream>
#include <unistd.h> // usleep
#include <spdlog/spdlog.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/fmt/fmt.h>
#include "Mesh.h"
#include "NodeId.h"
#include "MeshEvent.h"
#include "NetDiscovery.h"
#include "IpTools.h"

const std::string serviceName = "meshlinkd";
const std::string cachePath = "/var/lib/" + serviceName;
const std::string runDataPath = "/run/" + serviceName;

// 512 bits password (64 bytes)
static const std::vector<uint32_t> networkSecret = {
    0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000
};

static std::atomic<bool> exitServer(false);
static void signalHandler(int signum);
static invilite::NodeId nodeId(cachePath + "/node_id");
static invilite::NodeList nodeList(cachePath + "/node_list");

int main(int argc, char** argv) {
    spdlog::info("Mesh network information exchange service");
    CLI::App app{"Mesh network information exchange service"};
    //std::string filename;
    //app.add_option("-f,--file", filename, "File name")->required();

    bool daemon = false;
    app.add_flag("-d,--daemon", daemon, "Run as daemon");

    std::vector<std::string> nodes;
    app.add_option("--node", nodes, "Node address")->expected(-1);

    bool verbose = false;
    app.add_flag("-v,--verbose", verbose, "More logs");

    // Parse command line arguments
    CLI11_PARSE(app, argc, argv);

    // Set logger level
    if (verbose) {
        spdlog::set_level(spdlog::level::trace);
    } else {
        spdlog::set_level(spdlog::level::info);
    }

    // Register signals handler
    signal(SIGINT, signalHandler);
    signal(SIGTERM, signalHandler);

    // Get local network interfaces and addresses
    std::vector<invilite::NetworkInterface> interfacesList;
    invilite::IpTools::getLocalInterfaces(&interfacesList);

    uint16_t port = 8420;
    invilite::Mesh mesh(port, &nodeId, networkSecret);

    // QUEUE
    // const char* queueName = "/testQueue";

    // // Atrybuty kolejki
    // mq_attr attr;
    // attr.mq_flags = 0;      // Blokujące operacje I/O
    // attr.mq_maxmsg = 10;    // Maksymalna liczba komunikatów w kolejce
    // attr.mq_msgsize = 1024; // Maksymalny rozmiar komunikatu
    // attr.mq_curmsgs = 0;    // Liczba komunikatów aktualnie w kolejce (ustawiane przez system)

    // // Utworzenie kolejki komunikatów (O_CREAT - utwórz jeśli nie istnieje, O_RDWR - otwórz do odczytu i zapisu)
    // mqd_t mq = mq_open(queueName, O_CREAT | O_RDWR, 0644, &attr);
    // if (mq == (mqd_t)-1) {
    //     std::cerr << "Błąd przy tworzeniu kolejki: " << strerror(errno) << std::endl;
    //     return 1;
    // }

    // // Komunikat do wysłania
    // const char* message = "Hello, Message Queue!";
    // if (mq_send(mq, message, strlen(message) + 1, 0) == -1) {
    //     std::cerr << "Błąd przy wysyłaniu do kolejki: " << strerror(errno) << std::endl;
    //     mq_close(mq);
    //     mq_unlink(queueName); // Usunięcie kolejki
    //     return 1;
    // }
    // QUEUE

    // Add node addresses from command line
    for (const auto& node : nodes) {
        std::string address;
        int port = 8420;

        size_t colonPos = node.find(':');
        if (colonPos != std::string::npos) {
            // Znaleziono port, rozdziel adres i port
            address = node.substr(0, colonPos);
            port = std::stoi(node.substr(colonPos + 1)); // Konwersja string na int
        } else {
            // Tylko adres, użyj domyślnego portu
            address = node;
        }

        mesh.addNode(address, port);
    }

    // Load known node addresses from cache file
    const std::set<Node>& allEntries = nodeList.getAll();
    for (const Node& node: allEntries) {
        mesh.addNode(node.address, node.port);
    }

    mesh.setOnReceivedCallback([](const invilite::MeshEvent* event, const std::array<uint8_t, 16>* remoteNodeId) {
        std::cout << "Dane odebrane od węzła: ";
        for (auto byte : *remoteNodeId) {
            std::cout << std::hex << static_cast<int>(byte);
        }
        std::cout << "\nTopic: ";
        for (auto byte : event->getTopic()) {
            std::cout << static_cast<char>(byte); // Zakładając, że topic jest ciągiem znaków
        }
        std::cout << "\nDane: ";
        for (auto byte : event->getData()) {
            std::cout << static_cast<char>(byte); // Zakładając, że data jest ciągiem znaków
        }
        std::cout << std::endl;
    });

    // Starting mesh network ...
    spdlog::debug("Starting mesh network with local id \"{}\" ...", nodeId.getIdAsString());
    mesh.start();

    NetDiscovery discovery(8420);

    // Discover other nodes in local network
    discovery.onDiscover([&interfacesList, &mesh](const std::string &address) {
        if (!invilite::IpTools::isLocalAddress(&interfacesList, address)) {
            if (nodeList.add({address, 8420})) {
                //std::cout << "New node discovered in local network [" << address << "]" << std::endl;
                spdlog::debug("New node discovered in local network [{}]", address);
                mesh.addNode(address, 8420);
            }
        }
    });
    discovery.startListening();

    //usleep(100000); // Sleep na 100ms
    // Discovery service should broadcast periodically only when there is no connection to any peer,
    // after connecting to any other node, node list will be downloaded
    discovery.discovery();
    //usleep(1000000); // Sleep na 1000ms

    while(!exitServer.load(std::memory_order_relaxed)) {
        usleep(100000); // Sleep na 100ms
    }

    try {
        discovery.stopListening();
    } catch (const std::exception &e) {
        std::cerr << "Exception caught when stopping discovery service: " << e.what() << std::endl;
    }

    try {
        std::cout << "Stopping mesh network ..." << std::endl;
        mesh.stop();
    } catch (const std::exception &e) {
        std::cerr << "Exception caught when stopping mesh service: " << e.what() << std::endl;
    }

    // Zamknięcie i usunięcie kolejki
    //mq_close(mq);
    //mq_unlink(queueName);

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
