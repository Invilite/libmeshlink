#include "meshlink/observed_address.h"

#include <arpa/inet.h>

namespace invilite::Mesh::ObservedAddressCodec {

namespace {
    constexpr uint8_t FAMILY_IPV4 = 4;
    constexpr uint8_t FAMILY_IPV6 = 6;
}

std::vector<uint8_t> encode(const std::string& address) {
    uint8_t bytes[16];
    if (inet_pton(AF_INET, address.c_str(), bytes) == 1) {
        std::vector<uint8_t> payload{ FAMILY_IPV4 };
        payload.insert(payload.end(), bytes, bytes + 4);
        return payload;
    }
    if (inet_pton(AF_INET6, address.c_str(), bytes) == 1) {
        std::vector<uint8_t> payload{ FAMILY_IPV6 };
        payload.insert(payload.end(), bytes, bytes + 16);
        return payload;
    }
    return {};
}

std::optional<std::string> decode(std::span<const uint8_t> payload) {
    char text[INET6_ADDRSTRLEN];
    if (payload.size() == 1 + 4 && payload[0] == FAMILY_IPV4 && inet_ntop(AF_INET, payload.data() + 1, text, sizeof(text))) return std::string(text);
    if (payload.size() == 1 + 16 && payload[0] == FAMILY_IPV6 && inet_ntop(AF_INET6, payload.data() + 1, text, sizeof(text))) return std::string(text);
    return std::nullopt;
}

} // namespace invilite::Mesh::ObservedAddressCodec
