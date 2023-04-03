#include <iostream>
#include <cstring>
#include <thread>
#include <memory>
#include <uv.h>
#include <unistd.h> // usleep
#include "Mesh.h"

// sudo apt-get install libuv1-dev

const std::string serviceName = "meshlinkd";
const std::string cachePath = "/var/cache/" + serviceName;
const std::string runDataPath = "/run/" + serviceName;

static invilite::NodeList nodeList(cachePath + "/node_list");
static invilite::Mesh mesh(&nodeList);

int main() {
	std::cout << "Starting server ..." << std::endl;
    mesh.connect();

    while(true) {
    	usleep(10000); // Sleep na 10ms
    }

    return 0;
}