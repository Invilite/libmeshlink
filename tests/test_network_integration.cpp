// Integration tests: real Network instances in one process, talking over loopback TCP.
// Network logs to stderr; run `./run_test 2>/dev/null` for quiet output.
#include <gtest/gtest.h>
#include "meshlink/network.h"
#include "test_helpers.h"

#include <atomic>
#include <filesystem>
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

size_t countOpenFileDescriptors() {
    return static_cast<size_t>(std::distance(std::filesystem::directory_iterator("/proc/self/fd"), std::filesystem::directory_iterator{}));
}

// Tracks lifecycle events for one remote peer and checks they alternate: connected, disconnected, connected...
// Both callbacks fire on the I/O thread, so plain sequencing is enough; atomics only for the reading test thread.
struct PeerEventCounter : NetworkEventListener {
    explicit PeerEventCounter(PeerId watched) : watched(watched) {}
    void onPeerConnected(const PeerIdentity& identity) override {
        if (identity.getPeerId() != this->watched) return;
        if (this->isConnected) ++this->outOfOrder;                                          // connected twice without disconnect
        this->isConnected = true;
        ++this->connected;
    }
    void onPeerDisconnected(const PeerId& peerId) override {
        if (peerId != this->watched) return;
        if (!this->isConnected) ++this->outOfOrder;
        this->isConnected = false;
        ++this->disconnected;
    }
    PeerId            watched;
    std::atomic<bool> isConnected{false};
    std::atomic<int>  connected{0};
    std::atomic<int>  disconnected{0};
    std::atomic<int>  outOfOrder{0};
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

// B1: a newer record with the same address set (e.g. the peer restarted and re-signed) carries no new
// information about reachability — what we learned about those addresses must survive the version bump.
TEST(NetworkIntegrationTest, NewerRecordWithSameAddressesKeepsReachabilityKnowledge) {
    const auto secret = makeSecret();
    TestNode alpha(secret, "alpha");
    TestNode beta(secret, "beta");

    // Beta already knows an older version of Alpha's record and has history with its address.
    const auto olderCreatedAt = std::chrono::system_clock::now() - 1h;
    const auto olderRecord    = makeSignedRecord(*alpha.identity, { ipv4("127.0.0.1", alpha.port) }, olderCreatedAt);
    beta.directory->upsertPeer(olderRecord.peerId, [&](KnownPeer& entry, bool) {
        entry.record                        = olderRecord;
        entry.hasEverConnected              = true;
        entry.availability                  = AvailabilityState::Available;
        entry.consecutiveConnectionFailures = 2;
        entry.nextConnectionAttemptAt       = std::chrono::steady_clock::now() + 1h;           // keep Beta's topology from dialing Alpha
    });

    alpha.network->start();
    beta.network->start();
    alpha.network->connectToPeer("127.0.0.1", beta.port);                                          // Beta receives Alpha's fresh record via HELLO (inbound)

    ASSERT_TRUE(waitUntil([&] { const auto e = beta.knownPeer(alpha); return e && e->record.createdAt > olderCreatedAt + 30min; }, 5s));
    const auto entry = beta.knownPeer(alpha);
    EXPECT_TRUE(entry->hasEverConnected);
    EXPECT_EQ(entry->availability, AvailabilityState::Available);
    EXPECT_EQ(entry->consecutiveConnectionFailures, 2);

    alpha.network->stop();
    beta.network->stop();
}

// B4: when both peers dial each other, the tie-break keeps exactly one connection. Replacing the existing
// connection must close the old socket, and listener events must stay consistent. On the replacing side the swap is
// invisible. The other side may see the old connection's EOF before its own handshake for the new one completes —
// an inherent simultaneous-open race — and then reports disconnected → connected, which is still consistent.
TEST(NetworkIntegrationTest, TieBreakReplacementClosesOldConnectionAndStaysTransparent) {
    const auto secret = makeSecret();
    TestNode first(secret, "first");
    TestNode second(secret, "second");
    // The node with the smaller PeerId wins with its outbound connection. Let the larger one dial first,
    // so the smaller one's later dial replaces the existing connection on both sides.
    TestNode& smaller = first.identity->getPeerId() < second.identity->getPeerId() ? first : second;
    TestNode& larger  = (&smaller == &first) ? second : first;
    const auto eventsAtSmaller = std::make_shared<PeerEventCounter>(larger.identity->getPeerId());
    const auto eventsAtLarger  = std::make_shared<PeerEventCounter>(smaller.identity->getPeerId());
    smaller.network->addListener(eventsAtSmaller);
    larger.network->addListener(eventsAtLarger);
    smaller.network->start();
    larger.network->start();

    larger.network->connectToPeer("127.0.0.1", smaller.port);
    ASSERT_TRUE(waitUntil([&] { return eventsAtSmaller->connected == 1 && eventsAtLarger->connected == 1; }, 5s));
    std::this_thread::sleep_for(300ms);                                                       // let HELLO/PEX/probes settle
    const size_t descriptorsBeforeReplacement = countOpenFileDescriptors();

    smaller.network->connectToPeer("127.0.0.1", larger.port);
    std::this_thread::sleep_for(1500ms);                                                      // handshake + replacement + cleanup

    EXPECT_EQ(smaller.network->getConnectedPeerCount(), 1u);
    EXPECT_EQ(larger.network->getConnectedPeerCount(), 1u);
    EXPECT_EQ(countOpenFileDescriptors(), descriptorsBeforeReplacement) << "old connection sockets leaked";
    for (const auto* events : { eventsAtSmaller.get(), eventsAtLarger.get() }) {
        EXPECT_EQ(events->outOfOrder, 0) << "connected reported twice without a disconnect in between";
        EXPECT_TRUE(events->isConnected);
    }

    larger.network->stop();
    smaller.network->stop();
}
