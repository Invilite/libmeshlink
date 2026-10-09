#pragma once

#include "meshlink/identity.h"
#include "meshlink/signed_peer_record.h"
#include "transport/platform.h"

#include <atomic>
#include <chrono>
#include <fstream>
#include <netinet/in.h>
#include <random>
#include <sys/socket.h>
#include <unistd.h>
#include <vector>

namespace invilite::Mesh::TestHelpers {

// Build a record signed by `identity` with an arbitrary createdAt: LocalIdentity::buildSelfRecord always stamps "now",
// and tests also need stale and future-dated records.
inline SignedPeerRecord makeSignedRecord(const LocalIdentity& identity, const std::vector<PeerAddress>& addresses, std::chrono::system_clock::time_point createdAt) {
    SignedPeerRecord rec;
    rec.peerId     = identity.getPeerId();
    rec.ed25519Pub = identity.getEd25519Pub();
    rec.x25519Pub  = identity.getX25519Pub();
    rec.createdAt  = std::chrono::time_point_cast<std::chrono::seconds>(createdAt);         // wire format has second precision
    rec.addresses  = addresses;
    rec.signature  = identity.sign(SignedPeerRecordCodec::serializeForSigning(rec.ed25519Pub, rec.x25519Pub, rec.createdAt, rec.addresses));
    return rec;
}

inline PeerAddress ipv4(const char* address, uint16_t port) { return { PeerAddress::Type::IPv4, address, port }; }
inline PeerAddress ipv6(const char* address, uint16_t port) { return { PeerAddress::Type::IPv6, address, port }; }

// A TCP port nobody listens on (also usable as a "connection refused" target). Chosen BELOW the kernel's ephemeral
// range: bind(0) and every outgoing connect take ports from that range, so an outgoing connection of some node in the
// same test could take the port between our probe and the listener's bind (seen as a rare "Cannot bind socket").
// Below the range only explicit binds compete.
inline uint16_t pickUnusedPort() {
    static const uint16_t ephemeralStart = [] {
        std::ifstream range("/proc/sys/net/ipv4/ip_local_port_range");
        unsigned low = 32768;
        range >> low;
        return static_cast<uint16_t>(low > 12000 ? low : 32768);
    }();
    static std::atomic<uint16_t> next{ static_cast<uint16_t>(ephemeralStart - 10000 + std::random_device{}() % 5000) };   // random start: two test runs rarely collide

    for (int attempt = 0; attempt < 10000; ++attempt) {
        uint16_t port = next.fetch_add(1);
        if (port >= ephemeralStart) { next = static_cast<uint16_t>(ephemeralStart - 10000); port = next.fetch_add(1); }

        // Free on IPv4 and IPv6 alike (nodes listen on "::"): try the dual-stack wildcard
        const int fd = ::socket(AF_INET6, SOCK_STREAM, 0);
        const int dualStack = 0;
        ::setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &dualStack, sizeof(dualStack));
        sockaddr_in6 address{};
        address.sin6_family = AF_INET6;
        address.sin6_addr   = in6addr_any;
        address.sin6_port   = htons(port);
        const bool free = ::bind(fd, reinterpret_cast<sockaddr*>(&address), sizeof(address)) == 0;
        ::close(fd);
        if (free) return port;
    }
    return 0;
}

// Stands in for a NAT that silently drops an unsolicited SYN. On loopback a SYN that arrives before the other side has
// opened its socket would be answered with RST; a listener on the same port whose only accept-queue slot is taken makes
// the kernel drop it instead, and leaves the port to SYN_SENT sockets bound next to it (SO_REUSEPORT).
struct SynBlackhole {
    int listener = ::socket(AF_INET, SOCK_STREAM, 0);
    int filler   = ::socket(AF_INET, SOCK_STREAM, 0);

    explicit SynBlackhole(uint16_t port) {
        Transport::Platform::allowLocalPortReuse(listener);
        sockaddr_in addr{};
        addr.sin_family      = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr.sin_port        = htons(port);
        ::bind(listener, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
        ::listen(listener, 0);
        ::connect(filler, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
    }
    ~SynBlackhole() { ::close(filler); ::close(listener); }
};

} // namespace invilite::Mesh::TestHelpers
