#include <string>
#include <cstdint>

struct Node {
    std::string address;
    uint16_t port;

    bool operator<(const Node& other) const {
        return std::tie(address, port) < std::tie(other.address, other.port);
    }
};