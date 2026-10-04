// Integration tests: real Network instances in one process, talking over loopback TCP.
// Network logs to stderr; run `./run_test 2>/dev/null` for quiet output.
#include <gtest/gtest.h>
#include "meshlink/network.h"
#include "test_helpers.h"

#include <functional>
#include <netinet/in.h>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>

using namespace invilite::Mesh;
using namespace invilite::Mesh::TestHelpers;
using namespace std::chrono_literals;

namespace {

// Ask the kernel for a currently unused TCP port. The socket is closed right away, so the port is free
// (tiny reuse race, acceptable in tests). Closed and never re-listened, it also serves as a "connection refused" target.
uint16_t pickUnusedPort() {
    const int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in addr{};
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    ::bind(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
    socklen_t len = sizeof(addr);
    ::getsockname(fd, reinterpret_cast<sockaddr*>(&addr), &len);
    ::close(fd);
    return ntohs(addr.sin_port);
}

bool waitUntil(const std::function<bool()>& condition, std::chrono::milliseconds timeout) {
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (std::chrono::steady_clock::now() < deadline) {
        if (condition()) return true;
        std::this_thread::sleep_for(50ms);
    }
    return condition();
}

// One mesh node: identity + directory + Network listening on its own loopback port.
struct TestNode {
    std::shared_ptr<LocalIdentity> identity  = std::make_shared<LocalIdentity>(LocalIdentity::generate());
    std::shared_ptr<PeerDirectory> directory = std::make_shared<PeerDirectory>();
    uint16_t                       port      = pickUnusedPort();
    std::unique_ptr<Network>       network;

    TestNode(const std::shared_ptr<std::array<uint8_t, 64>>& secret, const std::string& name) {
        NetworkConfig config;
        config.listenPort         = this->port;
        config.nodeName           = name;
        config.announcedAddresses = { ipv4("127.0.0.1", this->port) };
        this->network = std::make_unique<Network>(this->identity, secret, this->directory, config);
    }

    std::optional<KnownPeer> knownPeer(const TestNode& other) const { return this->directory->findPeer(other.identity->getPeerId()); }

    bool seesAsAvailable(const TestNode& other) const {
        const auto entry = this->knownPeer(other);
        return entry && entry->availability == AvailabilityState::Available;
    }
};

std::shared_ptr<std::array<uint8_t, 64>> makeSecret() {
    auto secret = std::make_shared<std::array<uint8_t, 64>>();
    secret->fill(0x42);
    return secret;
}

} // namespace

TEST(NetworkIntegrationTest, TwoNodesConnectAndExchangeHello) {
    const auto secret = makeSecret();
    TestNode alpha(secret, "alpha");
    TestNode beta(secret, "beta");
    alpha.network->start();
    beta.network->start();

    beta.network->connectToPeer("127.0.0.1", alpha.port);

    EXPECT_TRUE(waitUntil([&] { return alpha.network->getConnectedPeerCount() == 1 && beta.network->getConnectedPeerCount() == 1; }, 5s));
    EXPECT_TRUE(waitUntil([&] { return alpha.knownPeer(beta).has_value() && beta.knownPeer(alpha).has_value(); }, 5s));
    // Beta dialed Alpha's announced address → direct evidence it works.
    EXPECT_TRUE(waitUntil([&] { return beta.seesAsAvailable(alpha); }, 5s));

    beta.network->stop();
    alpha.network->stop();
}

// The motivating scenario from the design: Beta and Gamma only dial the hub (Alpha). Via probe + PEX
// every node must end up seeing every other node as Available.
TEST(NetworkIntegrationTest, StarTopologyConvergesToFullKnowledge) {
    const auto secret = makeSecret();
    TestNode alpha(secret, "alpha");
    TestNode beta(secret, "beta");
    TestNode gamma(secret, "gamma");
    alpha.network->start();
    beta.network->start();
    gamma.network->start();

    beta.network->connectToPeer("127.0.0.1", alpha.port);
    gamma.network->connectToPeer("127.0.0.1", alpha.port);

    const bool converged = waitUntil([&] {
        return alpha.seesAsAvailable(beta) && alpha.seesAsAvailable(gamma) && beta.seesAsAvailable(alpha) && beta.seesAsAvailable(gamma) && gamma.seesAsAvailable(alpha) && gamma.seesAsAvailable(beta);
    }, 15s);
    EXPECT_TRUE(converged);

    gamma.network->stop();
    beta.network->stop();
    alpha.network->stop();
}

// B2: after one probe finishes, the next eligible peer must be probed — the single-probe-in-flight guard
// must never stay stuck. Both peers point at ports nobody listens on, so each probe fails almost instantly
// (connection refused), which is exactly the timing that exposed the original ordering bug.
TEST(NetworkIntegrationTest, ProbesContinueAfterFastFailingProbe) {
    const auto secret = makeSecret();
    TestNode node(secret, "prober");
    const auto ghostOne = LocalIdentity::generate();
    const auto ghostTwo = LocalIdentity::generate();
    for (const auto* ghost : { &ghostOne, &ghostTwo }) {
        auto record = makeSignedRecord(*ghost, { ipv4("127.0.0.1", pickUnusedPort()) }, std::chrono::system_clock::now());
        node.directory->upsertPeer(record.peerId, [&](KnownPeer& entry, bool) { entry.record = record; });
    }
    node.network->start();

    const auto probedAndFailed = [&](const LocalIdentity& ghost) {
        const auto entry = node.directory->findPeer(ghost.getPeerId());
        return entry && entry->availability == AvailabilityState::Unavailable && entry->consecutiveProbeFailures == 1;
    };
    EXPECT_TRUE(waitUntil([&] { return probedAndFailed(ghostOne) && probedAndFailed(ghostTwo); }, 3s));

    node.network->stop();
}
