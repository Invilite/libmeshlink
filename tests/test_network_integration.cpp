// Integration tests: real Network instances in one process, talking over loopback TCP.
// Network logs to stderr; run `./run_test 2>/dev/null` for quiet output.
#include <gtest/gtest.h>
#include "meshlink/network.h"
#include "network_test_node.h"

#include <atomic>
#include <filesystem>
#include <functional>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>

using namespace invilite::Mesh;
using namespace invilite::Mesh::TestHelpers;
using namespace std::chrono_literals;

namespace {

size_t countOpenFileDescriptors() {
    return static_cast<size_t>(std::distance(std::filesystem::directory_iterator("/proc/self/fd"), std::filesystem::directory_iterator{}));
}

// Tracks lifecycle events for one remote peer and checks they alternate: connected, disconnected, connected...
// Both callbacks fire on the I/O thread, so plain sequencing is enough; atomics only for the reading test thread.
struct PeerEventCounter : NetworkEventListener {
    explicit PeerEventCounter(PeerId watched) : watched(watched) {}
    void onPeerConnected(const PeerIdentity& identity) override {
        if (identity.getPeerId() != this->watched) return;
        if (this->isConnected) ++this->outOfOrder;
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
    // Beta dialed Alpha's announced address: direct evidence it works.
    EXPECT_TRUE(waitUntil([&] { return beta.seesAsAvailable(alpha); }, 5s));

    beta.network->stop();
    alpha.network->stop();
}

// The motivating scenario: Beta and Gamma only dial the hub (Alpha). Via probe + PEX
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

// After one probe finishes, the next eligible peer must be probed ; the single-probe-in-flight guard
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

// A newer record with the same address set (e.g. the peer restarted and re-signed) carries no new
// information about reachability: what we learned about those addresses must survive the version bump.
TEST(NetworkIntegrationTest, NewerRecordWithSameAddressesKeepsReachabilityKnowledge) {
    const auto secret = makeSecret();
    TestNode alpha(secret, "alpha");
    TestNode beta(secret, "beta");

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
    alpha.network->connectToPeer("127.0.0.1", beta.port);

    ASSERT_TRUE(waitUntil([&] { const auto e = beta.knownPeer(alpha); return e && e->record.createdAt > olderCreatedAt + 30min; }, 5s));
    const auto entry = beta.knownPeer(alpha);
    EXPECT_TRUE(entry->hasEverConnected);
    EXPECT_EQ(entry->availability, AvailabilityState::Available);
    EXPECT_EQ(entry->consecutiveConnectionFailures, 2);

    alpha.network->stop();
    beta.network->stop();
}

// When both peers dial each other, the tie-break keeps exactly one connection. Replacing the existing
// connection must close the old socket, and listener events must stay consistent. On the replacing side the swap is
// invisible. The other side may see the old connection's EOF before its own handshake for the new one completes
// (an inherent simultaneous-open race), and then reports disconnected -> connected, which is still consistent.
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
    std::this_thread::sleep_for(300ms);
    const size_t descriptorsBeforeReplacement = countOpenFileDescriptors();

    smaller.network->connectToPeer("127.0.0.1", larger.port);
    std::this_thread::sleep_for(1500ms);

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

// A peer that keeps refusing our dials must not stay Available forever (Topology would redial it without end).
// After connectionFailuresBeforeUnavailable failed dials it is handed to the probe as Unavailable.
// Topology is kept away (nextConnectionAttemptAt far ahead); connectToPeer dials regardless of backoff.
TEST(NetworkIntegrationTest, RepeatedDialFailuresMakeAvailablePeerUnavailable) {
    const auto secret = makeSecret();
    TestNode node(secret, "dialer");
    const auto ghost     = LocalIdentity::generate();
    const uint16_t port  = pickUnusedPort();
    const auto record    = makeSignedRecord(ghost, { ipv4("127.0.0.1", port) }, std::chrono::system_clock::now());
    node.directory->upsertPeer(record.peerId, [&](KnownPeer& entry, bool) {
        entry.record                        = record;
        entry.hasEverConnected              = true;
        entry.availability                  = AvailabilityState::Available;
        entry.consecutiveConnectionFailures = 1;
        entry.nextConnectionAttemptAt       = std::chrono::steady_clock::now() + 1h;
    });
    node.network->start();

    // Second failure: still below the threshold of 3: one bad moment must not demote a working peer
    node.network->connectToPeer("127.0.0.1", port);
    ASSERT_TRUE(waitUntil([&] { return node.directory->findPeer(record.peerId)->consecutiveConnectionFailures == 2; }, 3s));
    EXPECT_EQ(node.directory->findPeer(record.peerId)->availability, AvailabilityState::Available);

    node.network->connectToPeer("127.0.0.1", port);
    ASSERT_TRUE(waitUntil([&] { return node.directory->findPeer(record.peerId)->consecutiveConnectionFailures == 3; }, 3s));
    EXPECT_TRUE(waitUntil([&] { return node.directory->findPeer(record.peerId)->availability == AvailabilityState::Unavailable; }, 3s));

    // The probe now owns it: it is probed (and fails, nobody listens) with its own backoff channel
    EXPECT_TRUE(waitUntil([&] { return node.directory->findPeer(record.peerId)->consecutiveProbeFailures >= 1; }, 3s));
    EXPECT_TRUE(node.directory->findPeer(record.peerId)->hasEverConnected) << "demotion must not erase PEX evidence";

    node.network->stop();
}

// Once demoted, the peer comes back through the probe: when it is reachable again it becomes Available.
TEST(NetworkIntegrationTest, DemotedPeerReturnsToAvailableThroughProbe) {
    const auto secret = makeSecret();
    TestNode node(secret, "dialer");
    TestNode target(secret, "target");
    const auto record = makeSignedRecord(*target.identity, { ipv4("127.0.0.1", target.port) }, std::chrono::system_clock::now());
    node.directory->upsertPeer(record.peerId, [&](KnownPeer& entry, bool) {
        entry.record                        = record;
        entry.hasEverConnected              = true;
        entry.availability                  = AvailabilityState::Available;
        entry.consecutiveConnectionFailures = 2;
        entry.nextConnectionAttemptAt       = std::chrono::steady_clock::now() + 1h;     // keep Topology from dialing
        entry.nextProbeAllowedAt            = std::chrono::steady_clock::now() + 1500ms; // first probe only after the target is up
    });
    node.network->start();

    node.network->connectToPeer("127.0.0.1", target.port);
    ASSERT_TRUE(waitUntil([&] { const auto e = node.directory->findPeer(record.peerId); return e->availability != AvailabilityState::Available; }, 3s));

    target.network->start();
    EXPECT_TRUE(waitUntil([&] { return node.directory->findPeer(record.peerId)->availability == AvailabilityState::Available; }, 5s));
    EXPECT_EQ(node.directory->findPeer(record.peerId)->consecutiveConnectionFailures, 3) << "probe success must not reset the dial channel";

    target.network->stop();
    node.network->stop();
}

// A dead first address must not hide a working second one: the probe tries them all, in order
TEST(NetworkIntegrationTest, ProbeTriesEveryAddressUntilOneAnswers) {
    const auto secret = makeSecret();
    TestNode node(secret, "prober");
    TestNode target(secret, "target");
    const auto record = makeSignedRecord(*target.identity, { ipv4("127.0.0.1", pickUnusedPort()), ipv4("127.0.0.1", target.port) }, std::chrono::system_clock::now());
    node.directory->upsertPeer(record.peerId, [&](KnownPeer& entry, bool) { entry.record = record; });
    target.network->start();
    node.network->start();

    EXPECT_TRUE(waitUntil([&] { const auto e = node.directory->findPeer(record.peerId); return e && e->availability == AvailabilityState::Available; }, 5s));
    EXPECT_EQ(node.directory->findPeer(record.peerId)->consecutiveProbeFailures, 0);

    node.network->stop();
    target.network->stop();
}

// A peer behind NAT relative to us with only private addresses is not probed at all: it could never succeed
TEST(NetworkIntegrationTest, PeerBehindNatWithOnlyPrivateAddressesIsNotProbed) {
    const auto secret = makeSecret();
    TestNode node(secret, "public");
    const auto natted = LocalIdentity::generate();
    const auto record = makeSignedRecord(natted, { ipv4("172.16.1.10", 8420) }, std::chrono::system_clock::now());
    node.directory->upsertPeer(record.peerId, [&](KnownPeer& entry, bool) { entry.record = record; entry.reachedUsOverPublicInternet = true; });
    node.network->start();

    std::this_thread::sleep_for(1500ms);                                                      // several probe ticks
    const auto entry = node.directory->findPeer(record.peerId);
    EXPECT_EQ(entry->availability, AvailabilityState::Unknown);
    EXPECT_EQ(entry->consecutiveProbeFailures, 0);
    node.network->stop();
}

// The HELLO records where we met: a peer once seen from a public address that now dials us over a private one (it came
// into our LAN, or onto our VPN) gets its private addresses back
TEST(NetworkIntegrationTest, HelloOverPrivateAddressClearsBehindNatEvidence) {
    const auto secret = makeSecret();
    TestNode alpha(secret, "alpha");
    TestNode beta(secret, "beta");
    const auto record = makeSignedRecord(*alpha.identity, { ipv4("127.0.0.1", alpha.port) }, std::chrono::system_clock::now() - 1h);
    beta.directory->upsertPeer(record.peerId, [&](KnownPeer& entry, bool) { entry.record = record; entry.reachedUsOverPublicInternet = true; });
    alpha.network->start();
    beta.network->start();

    alpha.network->connectToPeer("127.0.0.1", beta.port);
    EXPECT_TRUE(waitUntil([&] { const auto e = beta.knownPeer(alpha); return e && !e->reachedUsOverPublicInternet; }, 5s));

    alpha.network->stop();
    beta.network->stop();
}

// The side that accepted the connection tells the dialer where it sees it coming from; the dialer remembers it
TEST(NetworkIntegrationTest, DialerLearnsTheAddressItIsSeenFrom) {
    const auto secret = makeSecret();
    TestNode alpha(secret, "alpha");
    TestNode beta(secret, "beta");
    alpha.network->start();
    beta.network->start();

    alpha.network->connectToPeer("127.0.0.1", beta.port);
    ASSERT_TRUE(waitUntil([&] { return !alpha.network->getObservedSelfAddresses().empty(); }, 5s));
    const auto observed = alpha.network->getObservedSelfAddresses();
    ASSERT_EQ(observed.size(), 1u);
    EXPECT_EQ(observed.front().address, "127.0.0.1");
    EXPECT_EQ(observed.front().reportedBy, beta.identity->getPeerId());
    EXPECT_TRUE(beta.network->getObservedSelfAddresses().empty());                           // it was dialed: nothing to learn

    alpha.network->stop();
    beta.network->stop();
}

// While a dial is still in progress, Topology (ticking every 3 s) must not pick the same peer again.
// The target listens with a full accept queue, so the kernel drops our SYNs and connect() hangs for the whole
// 5 s connect timeout, longer than one Topology tick. One dial gives one failure; a redial would add a second.
TEST(NetworkIntegrationTest, TopologyDoesNotRedialPeerWhileAttemptIsInProgress) {
    const int listener = ::socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in addr{};
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    ASSERT_EQ(::bind(listener, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)), 0);
    ASSERT_EQ(::listen(listener, 0), 0);
    socklen_t len = sizeof(addr);
    ::getsockname(listener, reinterpret_cast<sockaddr*>(&addr), &len);
    const int filler = ::socket(AF_INET, SOCK_STREAM, 0);                                       // occupies the only accept-queue slot
    ASSERT_EQ(::connect(filler, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)), 0);

    const auto secret = makeSecret();
    TestNode node(secret, "dialer");
    const auto silent = LocalIdentity::generate();
    const auto record = makeSignedRecord(silent, { ipv4("127.0.0.1", ntohs(addr.sin_port)) }, std::chrono::system_clock::now());
    node.directory->upsertPeer(record.peerId, [&](KnownPeer& entry, bool) {
        entry.record           = record;
        entry.hasEverConnected = true;
        entry.availability     = AvailabilityState::Available;                                  // a Topology candidate
    });
    node.network->start();

    ASSERT_TRUE(waitUntil([&] { return node.directory->findPeer(record.peerId)->consecutiveConnectionFailures >= 1; }, 9s));
    std::this_thread::sleep_for(3500ms);                                                      // a redial started one tick later would fail by now
    EXPECT_EQ(node.directory->findPeer(record.peerId)->consecutiveConnectionFailures, 1);

    node.network->stop();
    ::close(filler);
    ::close(listener);
}

// Raw TCP connect, true when the connection was accepted by a listener at that address.
static bool tcpConnects(int family, const std::string& address, uint16_t port) {
    const int fd = ::socket(family, SOCK_STREAM, 0);
    sockaddr_storage target{};
    socklen_t length = 0;
    if (family == AF_INET6) {
        auto* v6 = reinterpret_cast<sockaddr_in6*>(&target);
        v6->sin6_family = AF_INET6;
        v6->sin6_port   = htons(port);
        ::inet_pton(AF_INET6, address.c_str(), &v6->sin6_addr);
        length = sizeof(sockaddr_in6);
    } else {
        auto* v4 = reinterpret_cast<sockaddr_in*>(&target);
        v4->sin_family = AF_INET;
        v4->sin_port   = htons(port);
        ::inet_pton(AF_INET, address.c_str(), &v4->sin_addr);
        length = sizeof(sockaddr_in);
    }
    const bool connected = ::connect(fd, reinterpret_cast<sockaddr*>(&target), length) == 0;
    ::close(fd);
    return connected;
}

// listenAddress restricts which interface accepts connections (e.g. only a VPN address). Bound to the IPv4
// loopback, the node must accept there and refuse on the IPv6 loopback.
TEST(NetworkIntegrationTest, ListenAddressRestrictsAcceptingInterface) {
    const auto secret = makeSecret();
    TestNode node(secret, "restricted", [](NetworkConfig& config) { config.listenAddress = "127.0.0.1"; });
    node.network->start();

    EXPECT_TRUE(tcpConnects(AF_INET, "127.0.0.1", node.port));
    EXPECT_FALSE(tcpConnects(AF_INET6, "::1", node.port));

    node.network->stop();
}

// The default "::" listens on IPv4 and IPv6 (dual stack), whatever the OS default for IPV6_V6ONLY.
TEST(NetworkIntegrationTest, DefaultListenAddressAcceptsIpv4AndIpv6) {
    const auto secret = makeSecret();
    TestNode node(secret, "dualstack");
    node.network->start();

    EXPECT_TRUE(tcpConnects(AF_INET, "127.0.0.1", node.port));
    EXPECT_TRUE(tcpConnects(AF_INET6, "::1", node.port));

    node.network->stop();
}

// A listen address that is not a numeric IP fails loudly at start instead of silently listening everywhere.
TEST(NetworkIntegrationTest, NonNumericListenAddressFailsToStart) {
    const auto secret = makeSecret();
    TestNode node(secret, "misconfigured", [](NetworkConfig& config) { config.listenAddress = "localhost"; });
    EXPECT_THROW(node.network->start(), std::runtime_error);
}

namespace {

// Observes, on node A, how one flooding peer and one quiet peer are served. onPeerConnected runs on A's I/O thread,
// so stalling it for the "staller" peer freezes A's I/O long enough for both peers' data to pile up in A's sockets.
struct ReceiveFairnessObserver : NetworkEventListener {
    PeerId            flooder{}, quiet{}, staller{};
    std::atomic<bool> stalling{false};
    std::atomic<int>  flooderMessages{0};
    std::atomic<int>  flooderMessagesBeforeQuiet{-1};
    std::atomic<std::chrono::steady_clock::rep> quietArrivedAt{0};
    std::atomic<std::chrono::steady_clock::rep> lastFloodArrivedAt{0};

    void onPeerConnected(const PeerIdentity& identity) override {
        if (identity.getPeerId() != this->staller) return;
        this->stalling = true;
        std::this_thread::sleep_for(500ms);
    }
    void onMessageReceived(const NetworkMessage& message) override {                         // I/O thread, in processing order
        const auto now = std::chrono::steady_clock::now().time_since_epoch().count();
        if (message.source == this->flooder) {
            ++this->flooderMessages;
            this->lastFloodArrivedAt = now;
        } else if (message.source == this->quiet && this->flooderMessagesBeforeQuiet < 0) {
            this->flooderMessagesBeforeQuiet = this->flooderMessages.load();
            this->quietArrivedAt = now;
        }
    }
};

std::vector<uint8_t> applicationMessage(uint8_t group, size_t payloadSize) {
    std::vector<uint8_t> frame{ group, 0x00, 0x01 };                                          // group | subtype (2 B BE) | payload
    frame.resize(3 + payloadSize, 0xAB);
    return frame;
}

} // namespace

// A peer that has a lot to say must not make A ignore everybody else. With A's I/O frozen, the flooder queues
// 3000 messages and the quiet peer one. Once A resumes, the quiet peer's message must come after at most a few
// receive budgets of the flooder ; not after its whole backlog. And none of the flooder's messages may get stuck:
// frames already read into A's buffer are invisible to poll(), so the I/O loop must come back for them on its own.
// (The flooder connects last: with libstdc++'s unordered_map it is then served first in each round, which is the
// order that exposed the starvation.)
TEST(NetworkIntegrationTest, FloodingPeerDoesNotStarveOthers) {
    const auto secret = makeSecret();
    TestNode receiver(secret, "receiver");
    TestNode quiet(secret, "quiet");
    TestNode flooder(secret, "flooder");
    TestNode staller(secret, "staller");
    const auto observer = std::make_shared<ReceiveFairnessObserver>();
    observer->flooder = flooder.identity->getPeerId();
    observer->quiet   = quiet.identity->getPeerId();
    observer->staller = staller.identity->getPeerId();
    receiver.network->addListener(observer);
    for (auto* node : { &receiver, &quiet, &flooder, &staller }) node->network->start();

    quiet.network->connectToPeer("127.0.0.1", receiver.port);
    ASSERT_TRUE(waitUntil([&] { return receiver.network->getConnectedPeerCount() == 1; }, 5s));
    flooder.network->connectToPeer("127.0.0.1", receiver.port);
    ASSERT_TRUE(waitUntil([&] { return receiver.network->getConnectedPeerCount() == 2 && flooder.network->getConnectedPeerCount() == 1 && quiet.network->getConnectedPeerCount() == 1; }, 5s));
    std::this_thread::sleep_for(300ms);

    staller.network->connectToPeer("127.0.0.1", receiver.port);
    ASSERT_TRUE(waitUntil([&] { return observer->stalling.load(); }, 5s));

    constexpr int FLOOD = 3000;
    const PeerId receiverId = receiver.identity->getPeerId();
    for (int i = 0; i < FLOOD; ++i) ASSERT_GT(flooder.network->sendToPeer(receiverId, applicationMessage(0x01, 100)), 0);
    std::this_thread::sleep_for(50ms);                                                        // the flood reaches receiver's socket first
    ASSERT_GT(quiet.network->sendToPeer(receiverId, applicationMessage(0x01, 10)), 0);

    ASSERT_TRUE(waitUntil([&] { return observer->flooderMessagesBeforeQuiet.load() >= 0; }, 5s));
    EXPECT_LT(observer->flooderMessagesBeforeQuiet.load(), 500) << "quiet peer waited behind the flooder's backlog";
    ASSERT_TRUE(waitUntil([&] { return observer->flooderMessages.load() == FLOOD; }, 5s)) << "buffered frames got stuck: " << observer->flooderMessages.load();
    // The rest of the backlog is already in receiver's buffers when the quiet message arrives; draining it takes
    // milliseconds. Frames left in the Connection buffer without a socket event would wait for unrelated traffic
    // (PEX, ~1 s later) ; the time bound is what catches that.
    const auto drainTime = std::chrono::steady_clock::duration(observer->lastFloodArrivedAt.load() - observer->quietArrivedAt.load());
    EXPECT_LT(drainTime, 500ms) << "frames already in receiver's buffer waited for an unrelated socket event";

    for (auto* node : { &staller, &flooder, &quiet, &receiver }) node->network->stop();
}

namespace {

// Raw TCP client that never completes a handshake: what an attacker (or a slowloris) looks like to the accept path.
struct RawConnection {
    int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    explicit RawConnection(uint16_t port) {
        sockaddr_in addr{};
        addr.sin_family      = AF_INET;
        addr.sin_port        = htons(port);
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        connected = ::connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == 0;
    }
    ~RawConnection() { ::close(fd); }
    // True when the node closed this connection (EOF or reset) within `timeout`.
    bool closedByRemoteWithin(std::chrono::milliseconds timeout) const {
        const auto deadline = std::chrono::steady_clock::now() + timeout;
        while (std::chrono::steady_clock::now() < deadline) {
            pollfd pfd{ fd, POLLIN, 0 };
            if (::poll(&pfd, 1, 20) > 0) {
                char byte;
                const ssize_t n = ::recv(fd, &byte, 1, MSG_DONTWAIT);
                if (n == 0 || (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK)) return true;
            }
        }
        return false;
    }
    bool connected = false;
};

struct MessageCounter : NetworkEventListener {
    explicit MessageCounter(PeerId watched) : watched(watched) {}
    void onMessageReceived(const NetworkMessage& message) override { if (message.source == this->watched) ++this->messages; }
    PeerId           watched;
    std::atomic<int> messages{0};
};

} // namespace

// A node above inbound.soft is dismissed politely. The dismissed side must get the whole farewell: our HELLO,
// a PEX sample (so it learns where else to go) and GOODBYE(NoSlots), even though our half-close makes its I/O see EOF
// right behind them. It then backs off on
// the rejection channel and keeps the full node Available. The full node never reports it to listeners.
TEST(NetworkIntegrationTest, NodeAboveInboundSoftLimitIsDismissedWithFarewell) {
    const auto secret = makeSecret();
    TestNode full(secret, "full", [](NetworkConfig& config) { config.connectionLimits.inbound.soft = 1; });
    TestNode first(secret, "first");
    TestNode dismissed(secret, "dismissed");

    // A peer the full node has verified: the farewell PEX should hand it to the dismissed node
    const auto elsewhere = LocalIdentity::generate();
    const auto elsewhereRecord = makeSignedRecord(elsewhere, { ipv4("127.0.0.1", pickUnusedPort()) }, std::chrono::system_clock::now());
    full.directory->upsertPeer(elsewhereRecord.peerId, [&](KnownPeer& entry, bool) { entry.record = elsewhereRecord; entry.hasEverConnected = true; });

    const auto eventsAtFull = std::make_shared<PeerEventCounter>(dismissed.identity->getPeerId());
    full.network->addListener(eventsAtFull);
    for (auto* node : { &full, &first, &dismissed }) node->network->start();

    first.network->connectToPeer("127.0.0.1", full.port);
    ASSERT_TRUE(waitUntil([&] { return full.network->getConnectedPeerCount() == 1; }, 5s));
    dismissed.network->connectToPeer("127.0.0.1", full.port);

    ASSERT_TRUE(waitUntil([&] { const auto e = dismissed.knownPeer(full); return e && e->consecutiveNoSlotsRejections == 1; }, 5s)) << "GOODBYE(NoSlots) lost";
    const auto fullAsSeen = dismissed.knownPeer(full);
    EXPECT_EQ(fullAsSeen->availability, AvailabilityState::Available) << "a full node is reachable, so it must not be demoted";
    EXPECT_EQ(fullAsSeen->consecutiveConnectionFailures, 0);
    EXPECT_GT(fullAsSeen->nextConnectionAttemptAt, std::chrono::steady_clock::now() + 5s) << "no backoff after NoSlots";
    EXPECT_TRUE(dismissed.directory->findPeer(elsewhereRecord.peerId).has_value()) << "farewell PEX lost";

    EXPECT_TRUE(waitUntil([&] { return dismissed.network->getConnectedPeerCount() == 0; }, 5s));
    EXPECT_EQ(full.network->getConnectedPeerCount(), 1u);
    EXPECT_EQ(eventsAtFull->connected.load(), 0) << "a dismissed peer must stay invisible to listeners";
    EXPECT_EQ(eventsAtFull->disconnected.load(), 0);

    // A second refusal backs off longer (connectToPeer dials regardless of backoff)
    const auto firstBackoffUntil = dismissed.knownPeer(full)->nextConnectionAttemptAt;
    dismissed.network->connectToPeer("127.0.0.1", full.port);
    ASSERT_TRUE(waitUntil([&] { return dismissed.knownPeer(full)->consecutiveNoSlotsRejections == 2; }, 5s));
    EXPECT_GT(dismissed.knownPeer(full)->nextConnectionAttemptAt, firstBackoffUntil + 10s);

    for (auto* node : { &dismissed, &first, &full }) node->network->stop();
}

// Remembered peers survive a restart: a node given its address book back dials a peer that worked before by itself
TEST(NetworkIntegrationTest, ImportedAddressBookIsDialedAfterRestart) {
    const auto secret = makeSecret();
    TestNode listener(secret, "listener");
    listener.network->start();
    std::vector<RememberedPeer> remembered;
    {
        TestNode before(secret, "before");
        before.network->start();
        before.network->connectToPeer("127.0.0.1", listener.port);
        ASSERT_TRUE(waitUntil([&] { const auto e = before.knownPeer(listener); return e && e->hasEverConnected; }, 5s));
        remembered = before.network->exportKnownPeers();
        before.network->stop();
    }
    ASSERT_FALSE(remembered.empty());

    TestNode after(secret, "after");
    EXPECT_EQ(after.network->importKnownPeers(remembered), 1u);
    const auto entry = after.knownPeer(listener);
    ASSERT_TRUE(entry.has_value());
    EXPECT_TRUE(entry->hasEverConnected);
    EXPECT_EQ(entry->availability, AvailabilityState::Available);
    after.network->start();
    EXPECT_TRUE(waitUntil([&] { return after.network->getConnectedPeerCount() == 1; }, 10s)) << "Topology did not dial the remembered peer";
    EXPECT_EQ(after.network->importKnownPeers(remembered), 0u);                               // only before start()

    after.network->stop();
    listener.network->stop();
}

// The file may be tampered with: a record whose signature no longer matches is not taken; our own record is skipped
TEST(NetworkIntegrationTest, ImportRefusesTamperedAndOwnRecords) {
    const auto secret = makeSecret();
    TestNode node(secret, "node");
    const auto other = LocalIdentity::generate();
    SignedPeerRecord genuine = makeSignedRecord(other, { ipv4("127.0.0.1", pickUnusedPort()) }, std::chrono::system_clock::now());
    SignedPeerRecord tampered = genuine;
    tampered.addresses = { ipv4("10.9.8.7", 4242) };                                          // the signature covers the addresses
    const SignedPeerRecord own = node.identity->buildSelfRecord({ ipv4("127.0.0.1", node.port) });

    EXPECT_EQ(node.network->importKnownPeers({ { tampered, true }, { own, true } }), 0u);
    EXPECT_EQ(node.directory->size(), 0u);
    EXPECT_EQ(node.network->importKnownPeers({ { genuine, false } }), 1u);
    EXPECT_EQ(node.directory->findPeer(genuine.peerId)->availability, AvailabilityState::Unknown);   // never worked: the probe decides
}

// The snapshot the Router's STATE_REPORT is built from: links, limits, address book
TEST(NetworkIntegrationTest, DiagnosticsDescribeLinksLimitsAndAddressBook) {
    const auto secret = makeSecret();
    TestNode listener(secret, "listener");
    TestNode dialer(secret, "dialer");
    for (auto* node : { &listener, &dialer }) node->network->start();
    dialer.network->connectToPeer("127.0.0.1", listener.port);
    ASSERT_TRUE(waitUntil([&] { return listener.network->getConnectedPeerCount() == 1 && dialer.network->getConnectedPeerCount() == 1; }, 5s));
    ASSERT_TRUE(waitUntil([&] { return dialer.knownPeer(listener).has_value() && listener.knownPeer(dialer).has_value(); }, 5s));

    const NetworkDiagnostics atListener = listener.network->getDiagnostics();
    ASSERT_EQ(atListener.links.size(), 1u);
    EXPECT_EQ(atListener.links[0].peerId, dialer.identity->getPeerId());
    EXPECT_TRUE(atListener.links[0].inbound);
    EXPECT_GT(atListener.links[0].bytesReceived, 0u);                                          // HELLO at least
    EXPECT_EQ(atListener.activeInbound, 1u);
    EXPECT_EQ(atListener.activeOutbound, 0u);
    EXPECT_EQ(atListener.limits.inbound.soft, NetworkConfig{}.connectionLimits.inbound.soft);
    EXPECT_GE(atListener.knownPeers, 1u);

    const NetworkDiagnostics atDialer = dialer.network->getDiagnostics();
    ASSERT_EQ(atDialer.links.size(), 1u);
    EXPECT_FALSE(atDialer.links[0].inbound);
    EXPECT_GT(atDialer.links[0].bytesSent, 0u);
    EXPECT_EQ(atDialer.activeOutbound, 1u);
    EXPECT_EQ(atDialer.knownByAvailability[static_cast<size_t>(AvailabilityState::Available)], 1u);   // a successful dial proves the listener
    EXPECT_EQ(atDialer.inboundDismissedForNoSlots, 0u);

    for (auto* node : { &dialer, &listener }) node->network->stop();
}

TEST(NetworkIntegrationTest, DiagnosticsCountNoSlotsDismissals) {
    const auto secret = makeSecret();
    TestNode full(secret, "full", [](NetworkConfig& config) { config.connectionLimits.inbound.soft = 1; });
    TestNode first(secret, "first");
    TestNode dismissed(secret, "dismissed");
    for (auto* node : { &full, &first, &dismissed }) node->network->start();

    first.network->connectToPeer("127.0.0.1", full.port);
    ASSERT_TRUE(waitUntil([&] { return full.network->getConnectedPeerCount() == 1; }, 5s));
    EXPECT_EQ(full.network->getDiagnostics().inboundDismissedForNoSlots, 0u);
    dismissed.network->connectToPeer("127.0.0.1", full.port);
    EXPECT_TRUE(waitUntil([&] { return full.network->getDiagnostics().inboundDismissedForNoSlots == 1; }, 5s));
    EXPECT_EQ(full.network->getDiagnostics().links.size(), 1u);                               // a departing peer is not a link

    for (auto* node : { &dismissed, &first, &full }) node->network->stop();
}

// In the departure window only management messages are expected from the departing peer. Application data from it
// is a protocol violation ; it must never reach listeners.
TEST(NetworkIntegrationTest, ApplicationDataFromDepartingPeerIsNotDelivered) {
    const auto secret = makeSecret();
    TestNode full(secret, "full", [](NetworkConfig& config) { config.connectionLimits.inbound.soft = 1; });
    TestNode first(secret, "first");
    TestNode dismissed(secret, "dismissed");
    const auto messagesAtFull = std::make_shared<MessageCounter>(dismissed.identity->getPeerId());
    full.network->addListener(messagesAtFull);

    struct SendOnConnect : NetworkEventListener {
        Network*          network = nullptr;
        std::atomic<bool> sent{false};
        void onPeerConnected(const PeerIdentity& identity) override { this->sent = this->network->sendToPeer(identity.getPeerId(), applicationMessage(0x01, 50)) > 0; }
    };
    const auto sender = std::make_shared<SendOnConnect>();
    sender->network = dismissed.network.get();
    dismissed.network->addListener(sender);
    for (auto* node : { &full, &first, &dismissed }) node->network->start();

    first.network->connectToPeer("127.0.0.1", full.port);
    ASSERT_TRUE(waitUntil([&] { return full.network->getConnectedPeerCount() == 1; }, 5s));
    dismissed.network->connectToPeer("127.0.0.1", full.port);
    // The violation closes the connection at once, possibly before our farewell even goes out
    ASSERT_TRUE(waitUntil([&] { return sender->sent.load() && dismissed.network->getConnectedPeerCount() == 0; }, 5s));
    EXPECT_EQ(full.network->getConnectedPeerCount(), 1u);
    std::this_thread::sleep_for(300ms);

    EXPECT_EQ(messagesAtFull->messages.load(), 0);

    for (auto* node : { &dismissed, &first, &full }) node->network->stop();
}

// Above inbound.hard a connection is closed right after accept(): nothing is allocated for it, so connections
// that never finish a handshake cannot pile up. Handshakes in progress count towards the limit.
TEST(NetworkIntegrationTest, InboundAboveHardLimitIsClosedImmediately) {
    const auto secret = makeSecret();
    TestNode node(secret, "guarded", [](NetworkConfig& config) { config.connectionLimits.inbound = { .soft = 1, .hard = 2, .perAddress = 5 }; });
    node.network->start();

    {
        RawConnection firstHandshake(node.port), secondHandshake(node.port);
        ASSERT_TRUE(firstHandshake.connected && secondHandshake.connected);
        std::this_thread::sleep_for(100ms);

        RawConnection overLimit(node.port);
        EXPECT_TRUE(overLimit.closedByRemoteWithin(500ms));
        EXPECT_FALSE(firstHandshake.closedByRemoteWithin(200ms)) << "admitted handshakes must not be cut by the limit";
    }                                                                                         // close before stop(): stop() waits for handshake workers

    // Their slots come back once those connections are gone; a leak would lock the node out for good
    std::this_thread::sleep_for(200ms);
    {
        RawConnection afterwards(node.port), another(node.port);
        EXPECT_FALSE(afterwards.closedByRemoteWithin(200ms));
        EXPECT_FALSE(another.closedByRemoteWithin(200ms));
    }

    node.network->stop();
}

// One address cannot take all inbound capacity: other addresses (and the node's LAN neighbours) still get in.
TEST(NetworkIntegrationTest, InboundPerAddressLimitClosesExcessFromSameAddress) {
    const auto secret = makeSecret();
    TestNode node(secret, "guarded", [](NetworkConfig& config) { config.connectionLimits.inbound = { .soft = 8, .hard = 16, .perAddress = 2 }; });
    node.network->start();

    {
        RawConnection first(node.port), second(node.port);
        std::this_thread::sleep_for(100ms);
        RawConnection third(node.port);
        EXPECT_TRUE(third.closedByRemoteWithin(500ms));
        EXPECT_FALSE(first.closedByRemoteWithin(200ms));
    }

    node.network->stop();
}

// The handshake deadline counts from accept(). A client trickling a byte now and then (slowloris) must not reset the
// wait each time and hold a worker thread forever; it is cut at the deadline (5 s) and its slot returns.
TEST(NetworkIntegrationTest, SlowHandshakeIsCutAtDeadline) {
    const auto secret = makeSecret();
    TestNode node(secret, "guarded", [](NetworkConfig& config) { config.connectionLimits.inbound = { .soft = 1, .hard = 1, .perAddress = 5 }; });
    node.network->start();

    RawConnection slow(node.port);
    ASSERT_TRUE(slow.connected);
    const auto start = std::chrono::steady_clock::now();
    bool closed = false;
    while (!closed && std::chrono::steady_clock::now() - start < 8s) {
        const char byte = 0x00;
        ::send(slow.fd, &byte, 1, MSG_NOSIGNAL);                                              // one byte per second keeps a per-chunk timeout alive
        closed = slow.closedByRemoteWithin(1s);
    }
    EXPECT_TRUE(closed);
    EXPECT_LT(std::chrono::steady_clock::now() - start, 6500ms);

    // The slot comes back when the handshake worker ends, a moment after the socket was closed: allow it that moment
    bool admitted = false;
    for (const auto until = std::chrono::steady_clock::now() + 2s; !admitted && std::chrono::steady_clock::now() < until;) {
        RawConnection next(node.port);
        admitted = !next.closedByRemoteWithin(300ms);
    }
    EXPECT_TRUE(admitted);

    node.network->stop();
}

// The outbound hard limit is never exceeded, not even by explicit connectToPeer calls.
TEST(NetworkIntegrationTest, OutboundHardLimitIsNeverExceeded) {
    const auto secret = makeSecret();
    TestNode dialer(secret, "dialer", [](NetworkConfig& config) { config.connectionLimits.outbound = { .min = 0, .soft = 1, .hard = 1 }; });
    TestNode one(secret, "one");
    TestNode two(secret, "two");
    for (auto* node : { &dialer, &one, &two }) node->network->start();

    dialer.network->connectToPeer("127.0.0.1", one.port);
    dialer.network->connectToPeer("127.0.0.1", two.port);
    std::this_thread::sleep_for(1500ms);

    EXPECT_EQ(dialer.network->getConnectedPeerCount(), 1u);
    EXPECT_EQ(one.network->getConnectedPeerCount() + two.network->getConnectedPeerCount(), 1u);

    for (auto* node : { &dialer, &one, &two }) node->network->stop();
}

// stop() says GOODBYE and lets the remote close first. It returns quickly when the remote cooperates,
// and the remote sees an orderly disconnect.
TEST(NetworkIntegrationTest, StopDepartsGracefullyAndQuickly) {
    const auto secret = makeSecret();
    TestNode leaving(secret, "leaving");
    TestNode staying(secret, "staying");
    const auto eventsAtStaying = std::make_shared<PeerEventCounter>(leaving.identity->getPeerId());
    staying.network->addListener(eventsAtStaying);
    leaving.network->start();
    staying.network->start();
    leaving.network->connectToPeer("127.0.0.1", staying.port);
    ASSERT_TRUE(waitUntil([&] { return eventsAtStaying->connected == 1; }, 5s));

    const auto start = std::chrono::steady_clock::now();
    leaving.network->stop();
    EXPECT_LT(std::chrono::steady_clock::now() - start, 1s);
    EXPECT_TRUE(waitUntil([&] { return eventsAtStaying->disconnected == 1; }, 2s));
    EXPECT_EQ(staying.network->getConnectedPeerCount(), 0u);

    staying.network->stop();
}


// A peer that refused us before but now keeps our connection has room again: once the connection has settled, its
// refusal count starts over, so a later refusal starts from the shortest backoff instead of where the old series ended.
TEST(NetworkIntegrationTest, SettledConnectionResetsNoSlotsRejections) {
    const auto secret = makeSecret();
    TestNode dialer(secret, "dialer");
    TestNode target(secret, "target");
    const auto record = makeSignedRecord(*target.identity, { ipv4("127.0.0.1", target.port) }, std::chrono::system_clock::now());
    dialer.directory->upsertPeer(record.peerId, [&](KnownPeer& entry, bool) {
        entry.record = record; entry.hasEverConnected = true; entry.availability = AvailabilityState::Available;
        entry.consecutiveNoSlotsRejections = 3;
        entry.nextConnectionAttemptAt      = std::chrono::steady_clock::now() + 1h;           // Topology stays away; we dial explicitly
    });
    dialer.network->start();
    target.network->start();
    dialer.network->connectToPeer("127.0.0.1", target.port);
    ASSERT_TRUE(waitUntil([&] { return dialer.network->getConnectedPeerCount() == 1; }, 5s));
    EXPECT_EQ(dialer.directory->findPeer(record.peerId)->consecutiveNoSlotsRejections, 3) << "reset before the connection settled";

    EXPECT_TRUE(waitUntil([&] { return dialer.directory->findPeer(record.peerId)->consecutiveNoSlotsRejections == 0; }, 20s));

    dialer.network->stop();
    target.network->stop();
}

// stop() closes the internal queues; start() must open them again, so a restarted node works (and does not spin).
TEST(NetworkIntegrationTest, RestartAfterStopWorks) {
    const auto secret = makeSecret();
    TestNode node(secret, "restarting");
    TestNode other(secret, "other");
    other.network->start();
    node.network->start();
    node.network->stop();

    node.network->start();
    node.network->connectToPeer("127.0.0.1", other.port);
    EXPECT_TRUE(waitUntil([&] { return node.network->getConnectedPeerCount() == 1 && other.knownPeer(node).has_value(); }, 5s)) << "HELLO not processed after restart";

    // Queues left closed still hand out items, so everything above works, but every waitPop returns at once and the
    // management thread spins. An idle process must stay well below one core.
    const auto cpuTime = [] { timespec t{}; ::clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &t); return std::chrono::seconds(t.tv_sec) + std::chrono::nanoseconds(t.tv_nsec); };
    const auto cpuBefore = cpuTime();
    std::this_thread::sleep_for(1s);
    EXPECT_LT(cpuTime() - cpuBefore, 300ms) << "a thread spins after restart";

    node.network->stop();
    other.network->stop();
}

// The address book is bounded and unverified gossip cannot push out what we know works. Bounded already holds
// three entries that once worked (unreachable right now) and room for one more, taken by the gossiper's HELLO, proven
// by our own dial. The gossiper then hands over 30 unverified records: with only proven or connected entries left,
// every one of them must be dropped. A hostile peer can mint identities for free; they must not cost us real peers.
TEST(NetworkIntegrationTest, AddressBookStaysWithinLimitUnderGossip) {
    const auto secret = makeSecret();
    TestNode bounded(secret, "bounded", [](NetworkConfig& config) { config.maxKnownPeers = 4; });
    TestNode gossiper(secret, "gossiper", [](NetworkConfig& config) { config.initialPexBatchSize = 30; });

    std::vector<PeerId> gossip;
    for (int i = 0; i < 30; ++i) {
        const auto someone = LocalIdentity::generate();
        const auto record  = makeSignedRecord(someone, { ipv4("127.0.0.1", static_cast<uint16_t>(20000 + i)) }, std::chrono::system_clock::now());
        gossiper.directory->upsertPeer(record.peerId, [&](KnownPeer& entry, bool) { entry.record = record; entry.hasEverConnected = true; });
        gossip.push_back(record.peerId);
    }
    std::vector<PeerId> veterans;
    for (int i = 0; i < 3; ++i) {
        const auto veteran = LocalIdentity::generate();
        const auto record  = makeSignedRecord(veteran, { ipv4("127.0.0.1", pickUnusedPort()) }, std::chrono::system_clock::now());
        bounded.directory->upsertPeer(record.peerId, [&](KnownPeer& entry, bool) {
            entry.record = record; entry.hasEverConnected = true; entry.availability = AvailabilityState::Unavailable;
            entry.consecutiveProbeFailures = 4;
            entry.nextProbeAllowedAt = std::chrono::steady_clock::now() + 1h;                 // keep the probe away
        });
        veterans.push_back(record.peerId);
    }

    bounded.network->start();
    gossiper.network->start();
    bounded.network->connectToPeer("127.0.0.1", gossiper.port);

    ASSERT_TRUE(waitUntil([&] { return bounded.knownPeer(gossiper).has_value(); }, 5s));
    std::this_thread::sleep_for(500ms);

    EXPECT_EQ(bounded.directory->size(), 4u);
    for (const auto& veteran : veterans) EXPECT_TRUE(bounded.directory->findPeer(veteran).has_value()) << "an entry that once worked was pushed out by unverified gossip";
    for (const auto& record : gossip) EXPECT_FALSE(bounded.directory->findPeer(record).has_value());

    bounded.network->stop();
    gossiper.network->stop();
}

// A record whose flood reached nobody must not be booked as announced; otherwise anti-entropy treats it as fresh
// news already spread and picks it last. Here the only flood target (B) has its I/O frozen and its queue full, so the
// broadcast of D's newly proven record is refused; D's record must stay unannounced.
TEST(NetworkIntegrationTest, RecordIsNotMarkedAnnouncedWhenFloodReachedNobody) {
    const auto secret = makeSecret();
    TestNode announcer(secret, "announcer", [](NetworkConfig& config) { config.sendQueueLimitBytes = 64 * 1024; });
    TestNode frozen(secret, "frozen");
    TestNode staller(secret, "staller");
    TestNode fresh(secret, "fresh");

    // Freezes frozen's I/O thread when staller connects (onPeerConnected runs on the I/O thread)
    struct StallOnConnect : NetworkEventListener {
        PeerId            staller{};
        std::atomic<bool> stalling{false};
        void onPeerConnected(const PeerIdentity& identity) override {
            if (identity.getPeerId() != this->staller) return;
            this->stalling = true;
            std::this_thread::sleep_for(3s);
        }
    };
    const auto stall = std::make_shared<StallOnConnect>();
    stall->staller = staller.identity->getPeerId();
    frozen.network->addListener(stall);
    for (auto* node : { &announcer, &frozen, &staller, &fresh }) node->network->start();

    announcer.network->connectToPeer("127.0.0.1", frozen.port);
    ASSERT_TRUE(waitUntil([&] { return announcer.network->getConnectedPeerCount() == 1; }, 5s));
    std::this_thread::sleep_for(300ms);

    staller.network->connectToPeer("127.0.0.1", frozen.port);
    ASSERT_TRUE(waitUntil([&] { return stall->stalling.load(); }, 5s));

    // Fill announcer's queue towards frozen until it refuses even a tiny frame (a PEX frame is ~250 B)
    const PeerId frozenId = frozen.identity->getPeerId();
    for (const size_t size : { 16 * 1024, 1024, 64 }) {
        ssize_t result = 1;
        for (int i = 0; i < 5000 && result > 0; ++i) result = announcer.network->sendToPeer(frozenId, applicationMessage(0x01, size));
        ASSERT_LT(result, 0) << "queue never filled with " << size << " B messages";
    }

    // A newly proven record (announcer dials fresh) is flooded, to frozen only, which refuses it
    announcer.network->connectToPeer("127.0.0.1", fresh.port);
    ASSERT_TRUE(waitUntil([&] { const auto e = announcer.knownPeer(fresh); return e && e->hasEverConnected; }, 2s));
    std::this_thread::sleep_for(1500ms);                                                      // the flood queue drains once per second

    const auto entry = announcer.knownPeer(fresh);
    EXPECT_EQ(entry->announceCount, 0) << "booked as announced although nobody received it";
    EXPECT_EQ(entry->lastAnnouncedAt, std::chrono::steady_clock::time_point{});

    for (auto* node : { &fresh, &staller, &frozen, &announcer }) node->network->stop();
}

// Group 0xFF is Network's own protocol: a frame injected through the public send API would reach the neighbor as a genuine
// management message (here a GOODBYE that would end the connection).
TEST(NetworkIntegrationTest, ApplicationCannotSendManagementFrames) {
    const auto secret = makeSecret();
    TestNode alpha(secret, "alpha");
    TestNode beta(secret, "beta");
    alpha.network->start();
    beta.network->start();
    beta.network->connectToPeer("127.0.0.1", alpha.port);
    ASSERT_TRUE(waitUntil([&] { return alpha.network->getConnectedPeerCount() == 1 && beta.network->getConnectedPeerCount() == 1; }, 5s));

    const PeerId alphaId = alpha.identity->getPeerId();
    const std::vector<uint8_t> injectedGoodbye{ 0xFF, 0x00, 0x40, 0x00 };
    EXPECT_LT(beta.network->sendToPeer(alphaId, injectedGoodbye), 0);
    EXPECT_EQ(beta.network->sendToAllConnected(injectedGoodbye), 0u);
    EXPECT_LT(beta.network->sendToPeer(alphaId, { 0x01, 0x00 }), 0);                          // shorter than Group | Subtype
    EXPECT_GT(beta.network->sendToPeer(alphaId, applicationMessage(0x01, 10)), 0);
    EXPECT_GT(beta.network->sendToPeer(alphaId, applicationMessage(0xFE, 10)), 0);           // Router control passes

    std::this_thread::sleep_for(300ms);
    EXPECT_EQ(alpha.network->getConnectedPeerCount(), 1u);
    EXPECT_EQ(beta.network->getConnectedPeerCount(), 1u);

    beta.network->stop();
    alpha.network->stop();
}

// PEX_REQUEST: the Router asks the neighbor that forwarded a broadcast for the sender's record.
// The record here belongs to a node that was never online; it is not gossiped, so only the request can deliver it.
TEST(NetworkIntegrationTest, PexRequestFetchesRecordTheNeighborHolds) {
    const auto secret = makeSecret();
    TestNode alpha(secret, "alpha", [](NetworkConfig& c) { c.periodicPexMinInterval = 600s; c.periodicPexMaxInterval = 600s; });
    TestNode beta(secret, "beta", [](NetworkConfig& c) { c.periodicPexMinInterval = 600s; c.periodicPexMaxInterval = 600s; });
    alpha.network->start();
    beta.network->start();
    beta.network->connectToPeer("127.0.0.1", alpha.port);
    ASSERT_TRUE(waitUntil([&] { return alpha.network->getConnectedPeerCount() == 1 && beta.network->getConnectedPeerCount() == 1; }, 5s));

    const auto offline = LocalIdentity::generate();
    const SignedPeerRecord offlineRecord = makeSignedRecord(offline, { ipv4("192.0.2.1", 7000) }, std::chrono::system_clock::now());
    beta.directory->upsertPeer(offline.getPeerId(), [&](KnownPeer& kp, bool) { kp.record = offlineRecord; });
    PeerId unknownId;
    unknownId.fill(0x77);

    const PeerId betaId = beta.identity->getPeerId();
    EXPECT_FALSE(alpha.network->requestPeerRecords(betaId, {}));
    EXPECT_FALSE(alpha.network->requestPeerRecords(unknownId, { offline.getPeerId() }));     // not a neighbor
    EXPECT_FALSE(alpha.network->requestPeerRecords(betaId, std::vector<PeerId>(PexAnnounceCodec::MAX_RECORDS_PER_BATCH + 1, unknownId)));
    ASSERT_FALSE(alpha.directory->findPeer(offline.getPeerId()).has_value());

    ASSERT_TRUE(alpha.network->requestPeerRecords(betaId, { unknownId, offline.getPeerId() }));
    ASSERT_TRUE(waitUntil([&] { return alpha.directory->findPeer(offline.getPeerId()).has_value(); }, 5s));
    EXPECT_EQ(alpha.directory->findPeer(offline.getPeerId())->record.ed25519Pub, offline.getEd25519Pub());
    EXPECT_FALSE(alpha.directory->findPeer(unknownId).has_value());
    EXPECT_EQ(alpha.network->getConnectedPeerCount(), 1u);                                    // a request for unknown ids is no violation

    beta.network->stop();
    alpha.network->stop();
}

namespace {

// Records one peer's events in the order a listener sees them. The first message is held for a while: if messages
// travelled another thread than disconnects, the disconnect would overtake the messages still behind it.
struct PeerEventOrderRecorder : NetworkEventListener {
    explicit PeerEventOrderRecorder(PeerId watched) : watched(watched) {}
    void onMessageReceived(const NetworkMessage& message) override {
        if (message.source != this->watched) return;
        if (!this->heldFirst.exchange(true)) std::this_thread::sleep_for(300ms);
        this->record('m');
    }
    void onPeerConnected(const PeerIdentity& identity) override { if (identity.getPeerId() == this->watched) this->record('c'); }
    void onPeerDisconnected(const PeerId& peerId) override { if (peerId == this->watched) this->record('d'); }
    std::string events() const { std::lock_guard lock(this->mutex); return this->sequence; }

    PeerId              watched;
    std::atomic<bool>   heldFirst{false};
    mutable std::mutex  mutex;
    std::string         sequence;

private:
    void record(char event) { std::lock_guard lock(this->mutex); this->sequence += event; }
};

} // namespace

// Connects, messages and disconnects reach listeners on one thread in the order they happened: no message before the
// peer's connect, every message it sent before leaving before its disconnect, and none after it
TEST(NetworkIntegrationTest, PeerMessagesReachListenersBeforeItsDisconnect) {
    const auto secret = makeSecret();
    TestNode alpha(secret, "alpha");
    TestNode beta(secret, "beta");
    const auto recorder = std::make_shared<PeerEventOrderRecorder>(beta.identity->getPeerId());
    alpha.network->addListener(recorder);
    alpha.network->start();
    beta.network->start();
    beta.network->connectToPeer("127.0.0.1", alpha.port);
    ASSERT_TRUE(waitUntil([&] { return alpha.network->getConnectedPeerCount() == 1 && beta.network->getConnectedPeerCount() == 1; }, 5s));

    for (int i = 0; i < 5; ++i) ASSERT_GT(beta.network->sendToPeer(alpha.identity->getPeerId(), applicationMessage(0x10, 16)), 0);
    beta.network->stop();

    ASSERT_TRUE(waitUntil([&] { return recorder->events().find('d') != std::string::npos; }, 5s));
    std::this_thread::sleep_for(100ms);                                                       // anything late would show up now
    EXPECT_EQ(recorder->events(), "cmmmmmd");
    alpha.network->stop();
}
