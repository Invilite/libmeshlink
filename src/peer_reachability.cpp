#include "meshlink/peer_reachability.h"

#include <arpa/inet.h>

#include <array>
#include <cstring>
#include <string>

namespace invilite::Mesh {

namespace {
    bool isPrivateIpv4(const uint8_t a[4]) {
        return a[0] == 10                                       // 10/8
            || (a[0] == 172 && (a[1] & 0xF0) == 16)             // 172.16/12
            || (a[0] == 192 && a[1] == 168)                     // 192.168/16
            || (a[0] == 100 && (a[1] & 0xC0) == 64)             // 100.64/10 — carrier-grade NAT
            || (a[0] == 169 && a[1] == 254)                     // link-local
            || a[0] == 127;                                     // loopback
    }
}

bool isPrivateAddress(std::string_view address) {
    const std::string text(address);
    uint8_t v4[4];
    if (inet_pton(AF_INET, text.c_str(), v4) == 1) return isPrivateIpv4(v4);

    uint8_t v6[16];
    if (inet_pton(AF_INET6, text.c_str(), v6) != 1) return false;
    static constexpr std::array<uint8_t, 12> V4_MAPPED_PREFIX = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF };
    if (std::memcmp(v6, V4_MAPPED_PREFIX.data(), V4_MAPPED_PREFIX.size()) == 0) return isPrivateIpv4(v6 + 12);
    static constexpr std::array<uint8_t, 16> LOOPBACK = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
    return (v6[0] & 0xFE) == 0xFC                               // fc00::/7 — unique local
        || (v6[0] == 0xFE && (v6[1] & 0xC0) == 0x80)            // fe80::/10 — link-local
        || std::memcmp(v6, LOOPBACK.data(), LOOPBACK.size()) == 0;
}

std::vector<PeerAddress> dialableAddresses(const KnownPeer& peer) {
    std::vector<PeerAddress> addresses;
    for (const PeerAddress& address : peer.record.addresses) {
        if (address.port == 0) continue;
        if (peer.reachedUsOverPublicInternet && isPrivateAddress(address.address)) continue;
        addresses.push_back(address);
    }
    return addresses;
}

std::optional<bool> observedReachedUsOverPublicInternet(const std::string& connectedFromAddress, const std::string& dialedAddress, bool dialedAddressAnnounced) {
    if (!connectedFromAddress.empty()) return !isPrivateAddress(connectedFromAddress);
    if (dialedAddressAnnounced && isPrivateAddress(dialedAddress)) return false;
    return std::nullopt;
}

} // namespace invilite::Mesh
