#ifndef NODE_CONNECTION_H
#define NODE_CONNECTION_H

#include <set>
#include <mutex>
#include <atomic>
#include <string>
#include <vector>
#include <memory>
#include <thread>
#include <utility>
#include <unistd.h>
#include <iostream>
#include <algorithm>
#include <functional>
#include <cstring>
#include <iostream>
#include "TcpClient.h"

namespace invilite {

class NodeConnection {
public:
	NodeConnection(const std::string& address, uint16_t port);

protected:
	std::shared_ptr<TcpClient> tcpClient;

};

} // namespace invilite

#endif // NODE_CONNECTION_H