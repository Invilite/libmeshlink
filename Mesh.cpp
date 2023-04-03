#include <unistd.h> // usleep
#include "Mesh.h"

using namespace invilite;

Mesh::Mesh(NodeList* nodeList_): server(std::make_shared<invilite::TcpServer>(8420)), nodeList(nodeList_) {
}

void Mesh::connect() {
	// Start TCP server
	serverThread = std::thread(&invilite::TcpServer::start, server);
    serverThread.detach();

    usleep(100000); // Sleep na 100ms

    std::cout << "Connecting to nodes ..." << std::endl;

    std::shared_ptr<TcpClient> client = std::make_shared<TcpClient>();
    client->connect("127.0.0.1", 8420);

    int i = 0;
    while(i++ < 10) {
    	client->send("Example data");
    	usleep(1000000); // Sleep na 1000ms
    }
    client->disconnect();


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

	// // Start clients main loop
	// auto clientsThread = std::thread([this]() {
	// 	std::cout << "Starting libuv loop" << std::endl << std::flush;
    //     uv_run(this->loop, UV_RUN_DEFAULT);
    //     std::cout << "libuv loop stopped" << std::endl << std::flush;
    // });
    // clientsThread.detach();
}

void Mesh::disconnect() {

}
