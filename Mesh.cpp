#include <unistd.h> // usleep
#include <iostream>
#include <string>
#include <set>
#include <mutex>
#include <vector>
#include <chrono>
#include <algorithm>
#include <condition_variable>
#include "Mesh.h"

std::mutex ip_set_mutex;
std::set<std::string> ip_addresses;
std::condition_variable new_ip_address_cv;

void maintain_connections(int x) {
    std::vector<invilite::TcpClient> clients(x);
    std::vector<bool> connected(x, false);

    while (true) {
        for (int i = 0; i < x; ++i) {
            if (connected[i]) {
                continue;
            }

            std::unique_lock<std::mutex> lock(ip_set_mutex);
            if (ip_addresses.empty()) {
                new_ip_address_cv.wait(lock);
            }

            std::string address = *ip_addresses.begin();
            ip_addresses.erase(ip_addresses.begin());
            lock.unlock();

            int port = 8420; // Przykładowy numer portu
            clients[i].onConnect([i, &connected]() {
                connected[i] = true;
            });
            clients[i].onDisconnect([i, &connected]() {
                connected[i] = false;
            });
            clients[i].onDataReceived([](const std::string& data) {
                std::cout << "Received data: " << data << std::endl;
            });

            if (clients[i].connect(address, port)) {
                connected[i] = true;
            } else {
                lock.lock();
                ip_addresses.insert(address);
                lock.unlock();
            }
        }

        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
}

std::string convertToString(uint32_t type, const std::set<std::string>& data) {
    std::stringstream ss;
    ss << type << "@";
    for (auto it = data.begin(); it != data.end(); ++it) {
        ss << *it;
        if (std::next(it) != data.end()) {
            ss << ",";
        }
    }
    return ss.str();
}

std::string convertToString(uint32_t type, const std::vector<std::string>& data) {
    std::stringstream ss;
    ss << type << "@";
    for (auto it = data.begin(); it != data.end(); ++it) {
        ss << *it;
        if (std::next(it) != data.end()) {
            ss << ",";
        }
    }
    return ss.str();
}

std::pair<uint32_t, std::vector<std::string>> convertBack(const std::string& input) {
    uint32_t type;
    std::vector<std::string> data;

    size_t at_pos = input.find('@');
    if (at_pos != std::string::npos) {
        std::stringstream ss_type(input.substr(0, at_pos));
        ss_type >> type;

        std::stringstream ss_data(input.substr(at_pos + 1));
        std::string item;
        while (std::getline(ss_data, item, ',')) {
            data.push_back(item);
        }
    }

    return std::make_pair(type, data);
}

invilite::Mesh::Mesh(const std::string* nodeId, NodeList* nodeList_): MeshProtocol(nodeId), server(std::make_shared<invilite::TcpServer>(8420)), nodeList(nodeList_) {
	// Handle server connections
	server->onConnect([this](const std::shared_ptr<invilite::ClientHandler> &client) {
        this->onConnect(client);
    });

    server->onDisconnect([this](const std::shared_ptr<invilite::ClientHandler> &client) {
        this->onDisconnect(client);
    });

    server->onDataReceived([this](const std::shared_ptr<invilite::ClientHandler> &client, const std::string &data) {
        this->onServerDataReceived(client, data);
    });
}

void invilite::Mesh::connect() {
	// Start TCP server
	serverThread = std::thread(&invilite::TcpServer::start, server);
    serverThread.detach();

    usleep(100000); // Sleep na 100ms

    std::cout << "Connecting to nodes ..." << std::endl;
    const std::set<std::string>& allEntries = nodeList->getAll();

    for (const std::string& entry: allEntries) {
        std::cout << "Connecting to: " << entry << std::endl;
        connectToNode(entry, 8420);
    }

    // int x = 5; // Liczba połączeń do utrzymania

    // // Dodaj początkowy zestaw adresów IP
    // ip_addresses = {"127.0.0.1", "127.0.0.2", "127.0.0.3", "127.0.0.4", "127.0.0.5"};

    // std::thread connection_thread(maintain_connections, x);
    // connection_thread.detach();

    // // Przykład dodawania nowych adresów IP do zestawu
    // std::this_thread::sleep_for(std::chrono::seconds(5));
    // std::unique_lock<std::mutex> lock(ip_set_mutex);
    // ip_addresses.insert("127.0.0.6");
    // new_ip_address_cv.notify_one();
    // lock.unlock();

    // // Czekaj na zakończenie programu (w rzeczywistym przypadku może być zastąpione przez pętlę obsługującą wejście użytkownika)
    // std::cin.get();


    while(1) {
    	usleep(1000000); // Sleep na 1000ms	
    }

    // // Starting client connections
    // for (const auto& address: *nodeList) {
	//     std::cout << "Node address: " << address << std::endl;

	//     std::shared_ptr<TcpClient> client = std::make_shared<TcpClient>(loop,
	// 	    [](TcpClient* client, void* context) { // Dodajemy 'void* context' jako dodatkowy argument
	// 	        std::cout << "Connected" << std::endl << std::flush;
	// 	        std::cout << "Wysyłam dane ..." << std::endl << std::flush;

	// 	        // Wyslij dane do serwera
	// 	        client->send("Hello, world!");
	// 	    },
	// 	    [](TcpClient* client, int status, void* context) { // Dodajemy 'void* context' jako dodatkowy argument
	// 	        std::cout << "Disconnected" << std::endl << std::flush;
	// 	    },
	// 	    [](TcpClient* client, const std::string& message, void* context) { // Dodajemy 'void* context' jako dodatkowy argument
	// 	        std::cout << "Received: " << message << std::endl << std::flush;
	// 	    },
	// 	    nullptr); // Dodajemy 'nullptr' jako argument 'context'

	//     clients.push_back(client);

	//     std::cout << "Otwieram połączenie ..." << std::endl << std::flush;

	//     // Podłącz funkcje zwrotne
	//     client->connect(address, 8420);
	// }
}

void invilite::Mesh::disconnect() {

}

void invilite::Mesh::addNode(const std::string& address, const int port) {
    nodeList->add(address);
}

void invilite::Mesh::onNodeConnected(const std::string &nodeId) {
    std::cout << "New mesh node connected: " << nodeId << std::endl;

    sendDataTo(nodeId, "example-foo", "Lorem ipsum, fucking working");
}

void invilite::Mesh::onNodeDisconnected(const std::string &nodeId) {
    std::cout << "New mesh node disconnected: " << nodeId << std::endl;
}

void invilite::Mesh::onDataReceived(const std::string& nodeId, const std::string& dataName, const std::string& message) {
	std::cout << "Data received from node: " << nodeId << ", data name: " << dataName << ", data: " << message << std::endl;
}
