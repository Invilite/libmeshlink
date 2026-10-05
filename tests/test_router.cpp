// Router integration tests: real Network instances in one process over loopback TCP, a Router on top of each.
// Network and Router log to stderr; run `./run_test 2>/dev/null` for quiet output.
#include <gtest/gtest.h>
#include "meshlink/router.h"
#include "meshlink/router_wire.h"
#include "network_test_node.h"

#include <mutex>

using namespace invilite::Mesh;
using namespace invilite::Mesh::TestHelpers;
using namespace std::chrono_literals;

namespace {

bool hasExactlyNeighbors(const Router& router, std::vector<PeerId> expected) {
    std::vector<PeerId> actual = router.getNeighbors();
    std::sort(actual.begin(), actual.end());
    std::sort(expected.begin(), expected.end());
    return actual == expected;
}

void connect(TestNode& dialer, TestNode& listener) {
    const size_t dialerBefore = dialer.network->getConnectedPeerCount();
    dialer.network->connectToPeer("127.0.0.1", listener.port);
    ASSERT_TRUE(waitUntil([&] { return dialer.network->getConnectedPeerCount() == dialerBefore + 1; }, 5s));
}

struct DeliveryRecorder : RouterEventListener {
    void onMessageDelivered(const RoutedDelivery& delivery) override {
        std::lock_guard lock(this->mutex);
        this->deliveries.push_back(delivery);
    }

    size_t countOf(const PeerId& sender, uint64_t msgId) const {
        std::lock_guard lock(this->mutex);
        return static_cast<size_t>(std::count_if(this->deliveries.begin(), this->deliveries.end(), [&](const RoutedDelivery& d) { return d.sender == sender && d.msgId == msgId; }));
    }

    std::optional<RoutedDelivery> find(const PeerId& sender, uint64_t msgId) const {
        std::lock_guard lock(this->mutex);
        for (const auto& d : this->deliveries) if (d.sender == sender && d.msgId == msgId) return d;
        return std::nullopt;
    }

    size_t total() const {
        std::lock_guard lock(this->mutex);
        return this->deliveries.size();
    }

    mutable std::mutex           mutex;
    std::vector<RoutedDelivery>  deliveries;
};

using Edge = std::pair<size_t, size_t>;                                                       // (dialer, listener)

// Nodes in a fixed topology: each node may dial exactly its own edges (outbound soft = hard = its out-degree), so Topology
// adds no connections of its own and the graph stays as declared. Every node runs a Router with a delivery recorder.
struct RouterMesh {
    std::shared_ptr<std::array<uint8_t, 64>>        secret = makeSecret();
    std::vector<std::unique_ptr<TestNode>>          nodes;
    std::vector<std::unique_ptr<Router>>            routers;
    std::vector<std::shared_ptr<DeliveryRecorder>>  recorders;
    bool                                            ready = false;

    RouterMesh(size_t count, const std::vector<Edge>& edges, const std::function<void(size_t, RouterConfig&)>& adjustRouter = {}) {
        std::vector<uint16_t> outDegree(count, 0);
        std::vector<size_t>   degree(count, 0);
        for (const auto& [dialer, listener] : edges) { ++outDegree[dialer]; ++degree[dialer]; ++degree[listener]; }

        for (size_t i = 0; i < count; ++i) {
            this->nodes.push_back(std::make_unique<TestNode>(this->secret, "node" + std::to_string(i), [&](NetworkConfig& c) {
                c.connectionLimits.outbound = { .min = 0, .soft = outDegree[i], .hard = outDegree[i] };
                c.periodicPexMinInterval = 600s;
                c.periodicPexMaxInterval = 600s;
            }));
            this->nodes.back()->network->start();
        }

        // Dial the last edges first: a node uses its outbound slots before gossip tells it about anyone else
        for (auto it = edges.rbegin(); it != edges.rend(); ++it) {
            TestNode& dialer = *this->nodes[it->first];
            const size_t before = dialer.network->getConnectedPeerCount();
            dialer.network->connectToPeer("127.0.0.1", this->nodes[it->second]->port);
            if (!waitUntil([&] { return dialer.network->getConnectedPeerCount() > before; }, 5s)) return;
        }

        for (size_t i = 0; i < count; ++i) {
            RouterConfig config;
            if (adjustRouter) adjustRouter(i, config);
            this->routers.push_back(std::make_unique<Router>(*this->nodes[i]->network, this->nodes[i]->directory, this->nodes[i]->identity, config));
            this->recorders.push_back(std::make_shared<DeliveryRecorder>());
            this->routers.back()->addListener(this->recorders.back());
            this->routers.back()->start();
        }

        // Every node sees exactly its declared neighbors. Records of distant nodes are not required: gossip spreads a
        // record only after someone dialed it successfully, so distant senders are usually verified via PEX_REQUEST.
        this->ready = waitUntil([&] {
            for (size_t i = 0; i < count; ++i) if (this->routers[i]->getNeighbors().size() != degree[i]) return false;
            return true;
        }, 10s);
    }

    ~RouterMesh() {
        for (auto& router : this->routers) router->stop();
        for (auto& node : this->nodes) node->network->stop();
    }

    PeerId id(size_t i) const { return this->nodes[i]->identity->getPeerId(); }

    // Every node except `sender` delivered (sender, msgId) at least once
    bool allOthersDelivered(size_t sender, uint64_t msgId) const {
        for (size_t i = 0; i < this->nodes.size(); ++i) if (i != sender && this->recorders[i]->countOf(this->id(sender), msgId) == 0) return false;
        return true;
    }
};

std::vector<Edge> lineEdges(size_t count) {
    std::vector<Edge> edges;
    for (size_t i = 0; i + 1 < count; ++i) edges.push_back({ i, i + 1 });
    return edges;
}

// Router control frames (Group 0xFE neighbor-only subtypes) seen by one node's Network
struct ControlFrameRecorder : NetworkEventListener {
    void onMessageReceived(const NetworkMessage& message) override {
        if (message.group != RouterWire::ROUTER_PROTOCOL_GROUP || RouterWire::carriesRoutingHeader(message.group, message.subtype)) return;
        std::lock_guard lock(this->mutex);
        this->frames.push_back(message);
    }

    std::vector<UnknownDeliveryModeReport> unknownModeReports() const {
        std::lock_guard lock(this->mutex);
        std::vector<UnknownDeliveryModeReport> reports;
        for (const auto& frame : this->frames) {
            UnknownDeliveryModeReport report;
            if (frame.subtype == RouterWire::SUBTYPE_UNKNOWN_DELIVERY_MODE && RouterWire::decodeUnknownDeliveryMode(frame.payload, report)) reports.push_back(report);
        }
        return reports;
    }

    mutable std::mutex           mutex;
    std::vector<NetworkMessage>  frames;
};

// A broadcast built by hand — for frames a well-behaved Router would never send (forgeries, replays)
RoutedMessage craftBroadcast(const PeerId& claimedSender, const LocalIdentity& signer, std::vector<uint8_t> payload) {
    RoutedMessage m;
    m.group             = 0x10;
    m.subtype           = 0x0001;
    m.mode              = RoutingMode::Broadcast;
    m.ttlInitial        = 16;
    m.ttlRemaining      = 16;
    m.msgId             = 0x5EED0000ULL + payload.size();
    m.sentAtUnixSeconds = static_cast<uint32_t>(std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count());
    m.sender            = claimedSender;
    m.payload           = std::move(payload);
    m.signature         = signer.sign(RouterWire::bytesToSign(m));
    return m;
}

RoutedMessage craftBroadcastFrom(const LocalIdentity& sender, std::vector<uint8_t> payload) {
    return craftBroadcast(sender.getPeerId(), sender, std::move(payload));
}

// A valid frame of `sender`'s broadcast with the mode nibble replaced by one nobody knows; `distinct` changes the msgId
std::vector<uint8_t> frameWithUnknownMode(const LocalIdentity& sender, uint8_t mode, uint8_t distinct) {
    std::vector<uint8_t> frame = RouterWire::encode(craftBroadcastFrom(sender, std::vector<uint8_t>(distinct, distinct)));
    frame[3] = static_cast<uint8_t>(RouterWire::WIRE_VERSION << 4) | mode;
    return frame;
}

} // namespace

// ── Skeleton (R-2) ──────────────────────────────────────────────────────────

TEST(RouterTest, TracksNeighborsFromNetworkEvents) {
    const auto secret = makeSecret();
    TestNode alpha(secret, "alpha");
    TestNode beta(secret, "beta");
    TestNode gamma(secret, "gamma");
    alpha.network->start();
    beta.network->start();
    gamma.network->start();
    Router router(*alpha.network, alpha.directory, alpha.identity);
    router.start();

    connect(beta, alpha);
    connect(gamma, alpha);
    EXPECT_TRUE(waitUntil([&] { return hasExactlyNeighbors(router, { beta.identity->getPeerId(), gamma.identity->getPeerId() }); }, 5s));

    beta.network->stop();
    EXPECT_TRUE(waitUntil([&] { return hasExactlyNeighbors(router, { gamma.identity->getPeerId() }); }, 5s));

    router.stop();
    gamma.network->stop();
    alpha.network->stop();
}

// Neighbors connected before the Router started come from the seed in start(); a restarted Router starts from scratch
TEST(RouterTest, StartSeesNeighborsAlreadyConnectedAndRestartWorks) {
    const auto secret = makeSecret();
    TestNode alpha(secret, "alpha");
    TestNode beta(secret, "beta");
    alpha.network->start();
    beta.network->start();
    connect(beta, alpha);
    ASSERT_TRUE(waitUntil([&] { return alpha.network->getConnectedPeerCount() == 1; }, 5s));

    Router router(*alpha.network, alpha.directory, alpha.identity);
    router.start();
    EXPECT_TRUE(hasExactlyNeighbors(router, { beta.identity->getPeerId() }));

    router.stop();
    EXPECT_TRUE(router.getNeighbors().empty());
    router.start();
    EXPECT_TRUE(hasExactlyNeighbors(router, { beta.identity->getPeerId() }));

    beta.network->stop();
    EXPECT_TRUE(waitUntil([&] { return router.getNeighbors().empty(); }, 5s));
    router.stop();
    alpha.network->stop();
}

// Undecodable routed frames and not-yet-handled control frames are dropped by the Router alone: the connection stays
// and the Router keeps processing later events
TEST(RouterTest, BadRoutedAndControlFramesDoNotDisturbRouterOrConnection) {
    const auto secret = makeSecret();
    TestNode alpha(secret, "alpha");
    TestNode beta(secret, "beta");
    TestNode gamma(secret, "gamma");
    alpha.network->start();
    beta.network->start();
    gamma.network->start();
    Router router(*alpha.network, alpha.directory, alpha.identity);
    router.start();
    connect(beta, alpha);

    const PeerId alphaId = alpha.identity->getPeerId();
    EXPECT_GT(beta.network->sendToPeer(alphaId, { 0x01, 0x00, 0x01, 0xDE, 0xAD }), 0);                     // truncated routing header
    EXPECT_GT(beta.network->sendToPeer(alphaId, { RouterWire::ROUTER_PROTOCOL_GROUP, 0x7F, 0x7F }), 0);    // unknown control subtype

    connect(gamma, alpha);
    EXPECT_TRUE(waitUntil([&] { return hasExactlyNeighbors(router, { beta.identity->getPeerId(), gamma.identity->getPeerId() }); }, 5s));
    EXPECT_EQ(alpha.network->getConnectedPeerCount(), 2u);

    router.stop();
    gamma.network->stop();
    beta.network->stop();
    alpha.network->stop();
}

// ── BROADCAST as flooding (R-3) ─────────────────────────────────────────────

TEST(RouterTest, BroadcastCrossesLineAndEveryNodeDeliversOnce) {
    RouterMesh mesh(5, lineEdges(5));
    ASSERT_TRUE(mesh.ready);

    const auto msgId = mesh.routers[0]->broadcast(0x10, 0x0102, { 'h', 'i' });
    ASSERT_TRUE(msgId.has_value());
    ASSERT_TRUE(waitUntil([&] { return mesh.allOthersDelivered(0, *msgId); }, 5s));
    std::this_thread::sleep_for(300ms);                                                       // room for any duplicate to show up

    EXPECT_EQ(mesh.recorders[0]->total(), 0u);                                                // own broadcast is not delivered back
    for (size_t i = 1; i < 5; ++i) {
        EXPECT_EQ(mesh.recorders[i]->countOf(mesh.id(0), *msgId), 1u) << "node " << i;
        const auto delivery = mesh.recorders[i]->find(mesh.id(0), *msgId);
        ASSERT_TRUE(delivery.has_value());
        EXPECT_EQ(delivery->hopsTraveled, i);
        EXPECT_EQ(delivery->group, 0x10);
        EXPECT_EQ(delivery->subtype, 0x0102);
        EXPECT_EQ(delivery->payload, (std::vector<uint8_t>{ 'h', 'i' }));
    }
}

// In a full mesh every node receives each broadcast from several neighbors: duplicates must be suppressed
TEST(RouterTest, BroadcastInFullMeshIsDeliveredExactlyOnce) {
    std::vector<Edge> edges;
    for (size_t i = 0; i < 5; ++i) for (size_t j = i + 1; j < 5; ++j) edges.push_back({ i, j });
    RouterMesh mesh(5, edges);
    ASSERT_TRUE(mesh.ready);

    std::vector<uint64_t> ids;
    for (size_t i = 0; i < 5; ++i) ids.push_back(mesh.routers[i]->broadcast(0x10, 0, { static_cast<uint8_t>(i) }).value());
    for (size_t i = 0; i < 5; ++i) ASSERT_TRUE(waitUntil([&] { return mesh.allOthersDelivered(i, ids[i]); }, 5s));
    std::this_thread::sleep_for(300ms);

    for (size_t receiver = 0; receiver < 5; ++receiver) {
        EXPECT_EQ(mesh.recorders[receiver]->total(), 4u) << "node " << receiver;
        for (size_t sender = 0; sender < 5; ++sender) {
            if (sender != receiver) { EXPECT_EQ(mesh.recorders[receiver]->countOf(mesh.id(sender), ids[sender]), 1u); }
        }
    }
}

TEST(RouterTest, BroadcastFromLeafReachesOtherLeavesThroughHub) {
    RouterMesh mesh(5, { { 1, 0 }, { 2, 0 }, { 3, 0 }, { 4, 0 } });
    ASSERT_TRUE(mesh.ready);

    const uint64_t msgId = mesh.routers[1]->broadcast(0x10, 0, { 1 }).value();
    ASSERT_TRUE(waitUntil([&] { return mesh.allOthersDelivered(1, msgId); }, 5s));
    EXPECT_EQ(mesh.recorders[0]->find(mesh.id(1), msgId)->hopsTraveled, 1);
    for (size_t leaf = 2; leaf < 5; ++leaf) EXPECT_EQ(mesh.recorders[leaf]->find(mesh.id(1), msgId)->hopsTraveled, 2);
}

TEST(RouterTest, TtlLimitsHowFarBroadcastTravels) {
    RouterMesh mesh(4, lineEdges(4), [](size_t node, RouterConfig& c) { if (node == 0) c.broadcastTtl = 2; });
    ASSERT_TRUE(mesh.ready);

    const uint64_t msgId = mesh.routers[0]->broadcast(0x10, 0, { 1 }).value();
    ASSERT_TRUE(waitUntil([&] { return mesh.recorders[2]->countOf(mesh.id(0), msgId) == 1; }, 5s));
    std::this_thread::sleep_for(500ms);
    EXPECT_EQ(mesh.recorders[1]->countOf(mesh.id(0), msgId), 1u);
    EXPECT_EQ(mesh.recorders[3]->countOf(mesh.id(0), msgId), 0u);                            // third hop is beyond TTL 2
}

// A forgery dies at the first hop: neither delivered nor forwarded, and it does not occupy the msgId of anything genuine
TEST(RouterTest, ForgedBroadcastIsDroppedAtFirstHop) {
    RouterMesh mesh(3, lineEdges(3), [](size_t, RouterConfig& c) { c.unknownSenderWait = 300ms; });
    ASSERT_TRUE(mesh.ready);
    const PeerId toNode1 = mesh.id(1);

    // Node 0 claims node 2 as the sender but can only sign with its own key
    const RoutedMessage impersonation = craftBroadcast(mesh.id(2), *mesh.nodes[0]->identity, { 'f', 'a', 'k', 'e' });
    ASSERT_GT(mesh.nodes[0]->network->sendToPeer(toNode1, RouterWire::encode(impersonation)), 0);

    // A sender nobody knows: node 1 asks node 0 for the record, gets nothing, gives up after unknownSenderWait
    const auto stranger = LocalIdentity::generate();
    const RoutedMessage fromStranger = craftBroadcast(stranger.getPeerId(), stranger, { 's', 't', 'r', 'a', 'n', 'g', 'e', 'r' });
    ASSERT_GT(mesh.nodes[0]->network->sendToPeer(toNode1, RouterWire::encode(fromStranger)), 0);

    // A genuine broadcast after them still gets through — the Router kept working
    const uint64_t genuine = mesh.routers[0]->broadcast(0x10, 0, { 'o', 'k' }).value();
    ASSERT_TRUE(waitUntil([&] { return mesh.recorders[2]->countOf(mesh.id(0), genuine) == 1; }, 5s));
    std::this_thread::sleep_for(600ms);

    for (size_t i = 1; i < 3; ++i) {
        EXPECT_EQ(mesh.recorders[i]->countOf(mesh.id(2), impersonation.msgId), 0u) << "node " << i;
        EXPECT_EQ(mesh.recorders[i]->countOf(stranger.getPeerId(), fromStranger.msgId), 0u) << "node " << i;
        EXPECT_EQ(mesh.recorders[i]->total(), 1u) << "node " << i;
    }
}

TEST(RouterTest, ReplayedBroadcastIsDeliveredOnce) {
    RouterMesh mesh(3, lineEdges(3));
    ASSERT_TRUE(mesh.ready);

    const RoutedMessage genuine = craftBroadcast(mesh.id(0), *mesh.nodes[0]->identity, { 'r', 'e' });
    const std::vector<uint8_t> frame = RouterWire::encode(genuine);
    ASSERT_GT(mesh.nodes[0]->network->sendToPeer(mesh.id(1), frame), 0);
    ASSERT_TRUE(waitUntil([&] { return mesh.recorders[2]->countOf(mesh.id(0), genuine.msgId) == 1; }, 5s));

    ASSERT_GT(mesh.nodes[0]->network->sendToPeer(mesh.id(1), frame), 0);                      // the same frame again
    std::this_thread::sleep_for(500ms);
    EXPECT_EQ(mesh.recorders[1]->countOf(mesh.id(0), genuine.msgId), 1u);
    EXPECT_EQ(mesh.recorders[2]->countOf(mesh.id(0), genuine.msgId), 1u);
}

// docs/router.md 4.1: a node that lacks the sender's record asks the neighbor that forwarded the broadcast (PEX_REQUEST)
TEST(RouterTest, UnknownSenderRecordIsFetchedFromForwardingNeighbor) {
    RouterMesh mesh(3, lineEdges(3));
    ASSERT_TRUE(mesh.ready);
    mesh.nodes[2]->directory->removePeer(mesh.id(0));

    const uint64_t msgId = mesh.routers[0]->broadcast(0x10, 0, { 'k', 'e', 'y' }).value();
    ASSERT_TRUE(waitUntil([&] { return mesh.recorders[2]->countOf(mesh.id(0), msgId) == 1; }, 3s));
    EXPECT_TRUE(mesh.nodes[2]->directory->findPeer(mesh.id(0)).has_value());
}

// Flooding sends each broadcast to every neighbor except the one it came from: on a line that is one full send per node
TEST(RouterTest, FloodingNeverSendsBackToWhereMessageCameFrom) {
    RouterMesh mesh(3, lineEdges(3));
    ASSERT_TRUE(mesh.ready);

    const uint64_t msgId = mesh.routers[0]->broadcast(0x10, 0, { 1 }).value();
    ASSERT_TRUE(waitUntil([&] { return mesh.allOthersDelivered(0, msgId); }, 5s));
    std::this_thread::sleep_for(300ms);
    for (size_t i = 0; i < 2; ++i) EXPECT_EQ(mesh.routers[i]->getStatistics().fullMessagesSent, 1u) << "node " << i;
    EXPECT_EQ(mesh.routers[2]->getStatistics().fullMessagesSent, 0u);
    for (size_t i = 0; i < 3; ++i) EXPECT_EQ(mesh.routers[i]->getStatistics().duplicatesDropped, 0u) << "node " << i;
}

// After a restart the duplicate memory is empty: our own old broadcast coming back must still not be delivered to us
TEST(RouterTest, OwnBroadcastComingBackIsNotDelivered) {
    RouterMesh mesh(2, lineEdges(2));
    ASSERT_TRUE(mesh.ready);

    const RoutedMessage echo = craftBroadcast(mesh.id(0), *mesh.nodes[0]->identity, { 'e', 'c', 'h', 'o' });
    ASSERT_GT(mesh.nodes[1]->network->sendToPeer(mesh.id(0), RouterWire::encode(echo)), 0);
    const uint64_t control = mesh.routers[1]->broadcast(0x10, 0, { 1 }).value();               // sent after the echo, same link
    ASSERT_TRUE(waitUntil([&] { return mesh.recorders[0]->countOf(mesh.id(1), control) == 1; }, 5s));
    EXPECT_EQ(mesh.recorders[0]->countOf(mesh.id(0), echo.msgId), 0u);
    EXPECT_EQ(mesh.routers[0]->getStatistics().duplicatesDropped, 1u);                        // recognized at once, no record lookup
}

// The originator already has its message: a node that got it from someone else does not send it to the originator
TEST(RouterTest, ForwardingSkipsOriginatorAmongNeighbors) {
    RouterMesh mesh(3, { { 0, 1 }, { 0, 2 }, { 1, 2 } });
    ASSERT_TRUE(mesh.ready);

    // Node 1 relays node 0's broadcast to node 2; node 2's other neighbor is the originator itself
    const RoutedMessage relayed = craftBroadcast(mesh.id(0), *mesh.nodes[0]->identity, { 'r' });
    ASSERT_GT(mesh.nodes[1]->network->sendToPeer(mesh.id(2), RouterWire::encode(relayed)), 0);
    ASSERT_TRUE(waitUntil([&] { return mesh.recorders[2]->countOf(mesh.id(0), relayed.msgId) == 1; }, 5s));
    std::this_thread::sleep_for(300ms);
    EXPECT_EQ(mesh.routers[2]->getStatistics().fullMessagesSent, 0u);
}

// A message waiting for a record that never comes leaves the bounded verification queue after unknownSenderWait
TEST(RouterTest, ExpiredWaitFreesVerificationQueue) {
    RouterMesh mesh(3, lineEdges(3), [](size_t, RouterConfig& c) { c.unknownSenderWait = 300ms; c.pendingVerificationLimit = 1; });
    ASSERT_TRUE(mesh.ready);

    // Node 1 hands node 2 a broadcast from a stranger nobody knows: it occupies node 2's only verification slot
    const auto stranger = LocalIdentity::generate();
    ASSERT_GT(mesh.nodes[1]->network->sendToPeer(mesh.id(2), RouterWire::encode(craftBroadcast(stranger.getPeerId(), stranger, { 's' }))), 0);
    std::this_thread::sleep_for(700ms);

    // Node 2 lacks node 0's record too; with the slot free again it can wait for it
    mesh.nodes[2]->directory->removePeer(mesh.id(0));
    const uint64_t msgId = mesh.routers[0]->broadcast(0x10, 0, { 1 }).value();
    EXPECT_TRUE(waitUntil([&] { return mesh.recorders[2]->countOf(mesh.id(0), msgId) == 1; }, 3s));
}

// "Seen" is recorded only after the signature checks out: a forgery sent first must not squat the genuine message's id
TEST(RouterTest, ForgeryCannotSquatGenuineMessageId) {
    RouterMesh mesh(3, lineEdges(3));
    ASSERT_TRUE(mesh.ready);

    const RoutedMessage genuine = craftBroadcast(mesh.id(0), *mesh.nodes[0]->identity, { 'g', 'o', 'o', 'd' });
    RoutedMessage forged = genuine;
    forged.payload = { 'e', 'v', 'i', 'l' };                                                  // same msgId and length, signature no longer matches
    ASSERT_GT(mesh.nodes[0]->network->sendToPeer(mesh.id(1), RouterWire::encode(forged)), 0);
    ASSERT_GT(mesh.nodes[0]->network->sendToPeer(mesh.id(1), RouterWire::encode(genuine)), 0);

    ASSERT_TRUE(waitUntil([&] { return mesh.recorders[2]->countOf(mesh.id(0), genuine.msgId) == 1; }, 5s));
    for (size_t i = 1; i < 3; ++i) EXPECT_EQ(mesh.recorders[i]->find(mesh.id(0), genuine.msgId)->payload, genuine.payload) << "node " << i;
}

// One neighbor flooding broadcasts from unknown senders fills only its own share of the verification queue
TEST(RouterTest, OneNeighborCannotFillVerificationQueue) {
    RouterMesh mesh(3, { { 1, 0 }, { 2, 0 } }, [](size_t, RouterConfig& c) { c.pendingVerificationLimit = 4; c.pendingVerificationPerNeighbor = 2; c.unknownSenderWait = 2s; });
    ASSERT_TRUE(mesh.ready);

    // Node 1 parks more stranger broadcasts at node 0 than the whole queue holds; only its share is taken
    for (uint8_t i = 0; i < 5; ++i) {
        const auto stranger = LocalIdentity::generate();
        ASSERT_GT(mesh.nodes[1]->network->sendToPeer(mesh.id(0), RouterWire::encode(craftBroadcast(stranger.getPeerId(), stranger, { i }))), 0);
    }
    std::this_thread::sleep_for(200ms);

    // Node 2 relays a broadcast from a sender whose record only node 2 holds: node 0 still has room to wait for it
    const auto behindTwo = LocalIdentity::generate();
    mesh.nodes[2]->directory->upsertPeer(behindTwo.getPeerId(), [&](KnownPeer& kp, bool) { kp.record = makeSignedRecord(behindTwo, { ipv4("192.0.2.9", 7000) }, std::chrono::system_clock::now()); });
    const RoutedMessage relayed = craftBroadcast(behindTwo.getPeerId(), behindTwo, { 'o', 'k' });
    ASSERT_GT(mesh.nodes[2]->network->sendToPeer(mesh.id(0), RouterWire::encode(relayed)), 0);
    EXPECT_TRUE(waitUntil([&] { return mesh.recorders[0]->countOf(behindTwo.getPeerId(), relayed.msgId) == 1; }, 1500ms));
}

// After the duplicate memory overflowed, a replay of a message it had to forget is still refused
TEST(RouterTest, ReplayAfterDuplicateMemoryOverflowIsRefused) {
    RouterMesh mesh(2, lineEdges(2), [](size_t, RouterConfig& c) { c.duplicateCacheCapacity = 2; });
    ASSERT_TRUE(mesh.ready);

    std::vector<RoutedMessage> sent;
    for (uint8_t size = 1; size <= 3; ++size) {                                               // craftBroadcast derives msgId from the payload size
        sent.push_back(craftBroadcast(mesh.id(0), *mesh.nodes[0]->identity, std::vector<uint8_t>(size, 0x42)));
        ASSERT_GT(mesh.nodes[0]->network->sendToPeer(mesh.id(1), RouterWire::encode(sent.back())), 0);
    }
    ASSERT_TRUE(waitUntil([&] { return mesh.recorders[1]->total() == 3; }, 5s));

    ASSERT_GT(mesh.nodes[0]->network->sendToPeer(mesh.id(1), RouterWire::encode(sent.front())), 0);   // its key was evicted
    std::this_thread::sleep_for(400ms);
    EXPECT_EQ(mesh.recorders[1]->countOf(mesh.id(0), sent.front().msgId), 1u);
}

// The same message parked twice would waste the neighbor's share of the verification queue
TEST(RouterTest, RepeatedWaitingMessageTakesOneVerificationSlot) {
    RouterMesh mesh(2, { { 1, 0 } }, [](size_t, RouterConfig& c) { c.pendingVerificationPerNeighbor = 2; });
    ASSERT_TRUE(mesh.ready);

    const auto stranger = LocalIdentity::generate();
    const auto strangerFrame = RouterWire::encode(craftBroadcast(stranger.getPeerId(), stranger, { 's' }));
    ASSERT_GT(mesh.nodes[1]->network->sendToPeer(mesh.id(0), strangerFrame), 0);
    ASSERT_GT(mesh.nodes[1]->network->sendToPeer(mesh.id(0), strangerFrame), 0);

    const auto known = LocalIdentity::generate();                                             // node 1 holds its record, node 0 does not
    mesh.nodes[1]->directory->upsertPeer(known.getPeerId(), [&](KnownPeer& kp, bool) { kp.record = makeSignedRecord(known, { ipv4("192.0.2.9", 7000) }, std::chrono::system_clock::now()); });
    const RoutedMessage relayed = craftBroadcast(known.getPeerId(), known, { 'o', 'k' });
    ASSERT_GT(mesh.nodes[1]->network->sendToPeer(mesh.id(0), RouterWire::encode(relayed)), 0);
    EXPECT_TRUE(waitUntil([&] { return mesh.recorders[0]->countOf(known.getPeerId(), relayed.msgId) == 1; }, 1500ms));
}

// ── Modes reaching every node (R-4a) ────────────────────────────────────────

TEST(RouterTest, FloodModeChosenBySenderCrossesLine) {
    RouterMesh mesh(4, lineEdges(4));
    ASSERT_TRUE(mesh.ready);

    const uint64_t msgId = mesh.routers[0]->broadcast(0x10, 0, { 'f' }, RoutingMode::Flood).value();
    ASSERT_TRUE(waitUntil([&] { return mesh.allOthersDelivered(0, msgId); }, 5s));
    for (size_t i = 1; i < 4; ++i) {
        EXPECT_EQ(mesh.recorders[i]->countOf(mesh.id(0), msgId), 1u) << "node " << i;
        EXPECT_EQ(mesh.recorders[i]->find(mesh.id(0), msgId)->mode, RoutingMode::Flood);
    }
}

TEST(RouterTest, BroadcastRefusesPointToPointModes) {
    RouterMesh mesh(2, lineEdges(2));
    ASSERT_TRUE(mesh.ready);
    EXPECT_FALSE(mesh.routers[0]->broadcast(0x10, 0, { 1 }, RoutingMode::Unicast).has_value());
    EXPECT_FALSE(mesh.routers[0]->broadcast(0x10, 0, { 1 }, RoutingMode::Routed).has_value());
}

// A mode from a newer node is neither delivered nor forwarded; the connection stays usable
TEST(RouterTest, UnknownModeIsIgnored) {
    RouterMesh mesh(3, lineEdges(3));
    ASSERT_TRUE(mesh.ready);

    const RoutedMessage future = craftBroadcast(mesh.id(0), *mesh.nodes[0]->identity, { 'n', 'e', 'w' });
    std::vector<uint8_t> frame = RouterWire::encode(future);
    frame[3] = static_cast<uint8_t>(RouterWire::WIRE_VERSION << 4) | 0x4;                     // first unknown mode
    ASSERT_GT(mesh.nodes[0]->network->sendToPeer(mesh.id(1), frame), 0);

    const uint64_t control = mesh.routers[0]->broadcast(0x10, 0, { 1 }).value();              // sent after it, same link
    ASSERT_TRUE(waitUntil([&] { return mesh.allOthersDelivered(0, control); }, 5s));
    for (size_t i = 1; i < 3; ++i) EXPECT_EQ(mesh.recorders[i]->countOf(mesh.id(0), future.msgId), 0u) << "node " << i;
    EXPECT_EQ(mesh.routers[1]->getStatistics().fullMessagesSent, 1u);                         // only the control message
}

// ── Unknown mode is reported to the neighbor (R-4b a) ───────────────────────

TEST(RouterTest, UnknownModeIsReportedOncePerNeighborAndModeWithinInterval) {
    RouterMesh mesh(2, lineEdges(2));
    ASSERT_TRUE(mesh.ready);
    auto recorder = std::make_shared<ControlFrameRecorder>();
    mesh.nodes[0]->network->addListener(recorder);
    const LocalIdentity& sender = *mesh.nodes[0]->identity;

    const auto first = frameWithUnknownMode(sender, 0x4, 1);
    ASSERT_GT(mesh.nodes[0]->network->sendToPeer(mesh.id(1), first), 0);
    ASSERT_GT(mesh.nodes[0]->network->sendToPeer(mesh.id(1), frameWithUnknownMode(sender, 0x4, 2)), 0);   // same mode: no second reply
    ASSERT_GT(mesh.nodes[0]->network->sendToPeer(mesh.id(1), frameWithUnknownMode(sender, 0xF, 3)), 0);   // another mode: its own reply
    ASSERT_TRUE(waitUntil([&] { return recorder->unknownModeReports().size() >= 2; }, 5s));
    std::this_thread::sleep_for(300ms);

    const auto reports = recorder->unknownModeReports();
    ASSERT_EQ(reports.size(), 2u);
    RoutedMessage firstDecoded;
    ASSERT_EQ(RouterWire::decode(first[0], static_cast<uint16_t>(first[1] << 8 | first[2]), std::span<const uint8_t>(first).subspan(3), std::chrono::system_clock::now(), firstDecoded), RoutedMessageStatus::UnknownMode);
    EXPECT_EQ(reports[0], (UnknownDeliveryModeReport{ 0x4, { sender.getPeerId(), firstDecoded.msgId } }));
    EXPECT_EQ(reports[1].mode, 0xF);
    mesh.nodes[0]->network->removeListener(recorder);
}

TEST(RouterTest, UnknownModeIsReportedAgainAfterInterval) {
    RouterMesh mesh(2, lineEdges(2), [](size_t, RouterConfig& c) { c.unknownModeReportInterval = 1s; });
    ASSERT_TRUE(mesh.ready);
    auto recorder = std::make_shared<ControlFrameRecorder>();
    mesh.nodes[0]->network->addListener(recorder);
    const LocalIdentity& sender = *mesh.nodes[0]->identity;

    ASSERT_GT(mesh.nodes[0]->network->sendToPeer(mesh.id(1), frameWithUnknownMode(sender, 0x4, 1)), 0);
    ASSERT_TRUE(waitUntil([&] { return recorder->unknownModeReports().size() == 1; }, 5s));
    std::this_thread::sleep_for(1100ms);
    ASSERT_GT(mesh.nodes[0]->network->sendToPeer(mesh.id(1), frameWithUnknownMode(sender, 0x4, 2)), 0);
    EXPECT_TRUE(waitUntil([&] { return recorder->unknownModeReports().size() == 2; }, 5s));
    mesh.nodes[0]->network->removeListener(recorder);
}

// ── Plumtree (R-4b) ─────────────────────────────────────────────────────────

namespace {

// Ring of 8 with four chords: every node has degree 3, so flooding sends far more than N − 1 copies
std::vector<Edge> ringWithChords() {
    std::vector<Edge> edges;
    for (size_t i = 0; i < 8; ++i) edges.push_back({ i, (i + 1) % 8 });
    for (size_t i = 0; i < 4; ++i) edges.push_back({ i, i + 4 });
    return edges;
}

uint64_t totalFullMessagesSent(const RouterMesh& mesh) {
    uint64_t total = 0;
    for (const auto& router : mesh.routers) total += router->getStatistics().fullMessagesSent;
    return total;
}

// Broadcast from `sender`, wait until everyone else has it and copies have settled; returns full copies sent network-wide
uint64_t fullCopiesForOneBroadcast(RouterMesh& mesh, size_t sender, RoutingMode mode = RoutingMode::Broadcast) {
    const uint64_t before = totalFullMessagesSent(mesh);
    const uint64_t msgId = mesh.routers[sender]->broadcast(0x10, 0, { 'p' }, mode).value();
    EXPECT_TRUE(waitUntil([&] { return mesh.allOthersDelivered(sender, msgId); }, 5s));
    std::this_thread::sleep_for(300ms);                                                       // late duplicates and PRUNEs land
    return totalFullMessagesSent(mesh) - before;
}

void warmUp(RouterMesh& mesh, size_t sender) {
    for (int i = 0; i < 5; ++i) fullCopiesForOneBroadcast(mesh, sender);
}

} // namespace

TEST(RouterTest, PlumtreeSettlesToOneFullCopyPerNode) {
    RouterMesh mesh(8, ringWithChords());
    ASSERT_TRUE(mesh.ready);

    const uint64_t firstBroadcast = fullCopiesForOneBroadcast(mesh, 0);                       // every link eager: a flood
    EXPECT_GT(firstBroadcast, 7u);
    warmUp(mesh, 0);
    for (int i = 0; i < 3; ++i) EXPECT_EQ(fullCopiesForOneBroadcast(mesh, 0), 7u) << "broadcast " << i;   // N − 1: a spanning tree

    uint64_t announced = 0;
    for (const auto& router : mesh.routers) announced += router->getStatistics().announcementsSent;
    EXPECT_GT(announced, 0u);                                                                 // the rest of the links carry IHAVE
    EXPECT_GT(fullCopiesForOneBroadcast(mesh, 0, RoutingMode::Flood), 2 * 7u);               // FLOOD ignores the tree
}

// A node of the tree leaves: its neighbors' eager link is gone and fast repair (empty GRAFT to lazy links) restores
// delivery within a round trip — well before the GRAFT timeout would
TEST(RouterTest, PlumtreeRepairsQuicklyWhenTreeNodeLeaves) {
    RouterMesh mesh(8, ringWithChords());
    ASSERT_TRUE(mesh.ready);
    warmUp(mesh, 0);

    // The node that forwarded most in the last broadcast is an inner node of the tree
    std::vector<uint64_t> before;
    for (const auto& router : mesh.routers) before.push_back(router->getStatistics().fullMessagesSent);
    ASSERT_EQ(fullCopiesForOneBroadcast(mesh, 0), 7u);
    size_t inner = 1;
    for (size_t i = 1; i < 8; ++i) {
        if (mesh.routers[i]->getStatistics().fullMessagesSent - before[i] > mesh.routers[inner]->getStatistics().fullMessagesSent - before[inner]) inner = i;
    }
    ASSERT_GT(mesh.routers[inner]->getStatistics().fullMessagesSent - before[inner], 0u);

    mesh.routers[inner]->stop();
    mesh.nodes[inner]->network->stop();
    std::this_thread::sleep_for(300ms);                                                       // disconnects seen, fast repair sent

    const auto sentAt = std::chrono::steady_clock::now();
    const uint64_t msgId = mesh.routers[0]->broadcast(0x10, 0, { 'r' }).value();
    auto othersDelivered = [&] {
        for (size_t i = 1; i < 8; ++i) if (i != inner && mesh.recorders[i]->countOf(mesh.id(0), msgId) == 0) return false;
        return true;
    };
    ASSERT_TRUE(waitUntil(othersDelivered, 5s));
    EXPECT_LT(std::chrono::steady_clock::now() - sentAt, 400ms);                              // no GRAFT wait (500 ms)
}

// Link 1→2 made lazy by hand (PRUNE from node 2): node 2 only hears IHAVE and must GRAFT the message
TEST(RouterTest, AnnouncedMessageIsFetchedByGraftOnce) {
    RouterMesh mesh(3, lineEdges(3));
    ASSERT_TRUE(mesh.ready);
    ASSERT_GT(mesh.nodes[2]->network->sendToPeer(mesh.id(1), RouterWire::encodePrune()), 0);
    std::this_thread::sleep_for(200ms);

    const auto sentAt = std::chrono::steady_clock::now();
    const uint64_t msgId = mesh.routers[0]->broadcast(0x10, 0, { 'g' }).value();
    ASSERT_TRUE(waitUntil([&] { return mesh.recorders[2]->countOf(mesh.id(0), msgId) == 1; }, 5s));
    EXPECT_GE(std::chrono::steady_clock::now() - sentAt, 450ms);                              // came by GRAFT, not by push
    EXPECT_EQ(mesh.routers[2]->getStatistics().graftsSent, 1u);
    EXPECT_GE(mesh.routers[1]->getStatistics().announcementsSent, 1u);

    // GRAFT made the link eager again: the next message is pushed at once
    const uint64_t pushed = mesh.routers[0]->broadcast(0x10, 0, { 'h' }).value();
    EXPECT_TRUE(waitUntil([&] { return mesh.recorders[2]->countOf(mesh.id(0), pushed) == 1; }, 300ms));

    // A repeated GRAFT for the same message is not answered again
    const uint64_t sentByRelay = mesh.routers[1]->getStatistics().fullMessagesSent;
    const std::vector<RoutedMessageKey> again{ { mesh.id(0), msgId } };
    ASSERT_GT(mesh.nodes[2]->network->sendToPeer(mesh.id(1), RouterWire::encodeGraft(again)), 0);
    std::this_thread::sleep_for(300ms);
    EXPECT_EQ(mesh.routers[1]->getStatistics().fullMessagesSent, sentByRelay);
}

TEST(RouterTest, FloodModeIgnoresPrunedLinks) {
    RouterMesh mesh(3, lineEdges(3));
    ASSERT_TRUE(mesh.ready);
    ASSERT_GT(mesh.nodes[2]->network->sendToPeer(mesh.id(1), RouterWire::encodePrune()), 0);
    std::this_thread::sleep_for(200ms);

    const uint64_t msgId = mesh.routers[0]->broadcast(0x10, 0, { 'u' }, RoutingMode::Flood).value();
    EXPECT_TRUE(waitUntil([&] { return mesh.recorders[2]->countOf(mesh.id(0), msgId) == 1; }, 300ms));
    EXPECT_EQ(mesh.routers[2]->getStatistics().graftsSent, 0u);
}

// A relay that sets TTL 1 to win the race must not cut off the rest: the later genuine copy goes on
TEST(RouterTest, LowTtlFirstCopyDoesNotCutOffRestOfNetwork) {
    RouterMesh mesh(3, lineEdges(3));
    ASSERT_TRUE(mesh.ready);

    RoutedMessage message = craftBroadcastFrom(*mesh.nodes[0]->identity, { 't', 't', 'l' });
    message.ttlRemaining = 1;                                                                 // unsigned: any relay can do this
    ASSERT_GT(mesh.nodes[0]->network->sendToPeer(mesh.id(1), RouterWire::encode(message)), 0);
    ASSERT_TRUE(waitUntil([&] { return mesh.recorders[1]->countOf(mesh.id(0), message.msgId) == 1; }, 5s));
    EXPECT_EQ(mesh.recorders[2]->countOf(mesh.id(0), message.msgId), 0u);                    // TTL ended at node 1

    message.ttlRemaining = 16;
    ASSERT_GT(mesh.nodes[0]->network->sendToPeer(mesh.id(1), RouterWire::encode(message)), 0);
    EXPECT_TRUE(waitUntil([&] { return mesh.recorders[2]->countOf(mesh.id(0), message.msgId) == 1; }, 5s));
    EXPECT_EQ(mesh.recorders[1]->countOf(mesh.id(0), message.msgId), 1u);                    // still delivered once
    EXPECT_EQ(mesh.routers[1]->getStatistics().prunesSent, 0u);                               // the better path is not pruned
}

// ── Review findings (R-4) ───────────────────────────────────────────────────

// An unverified duplicate claiming TTL 255 must not leave the relay with a copy nobody can encode: the genuine message
// still reaches the rest of the network
TEST(RouterTest, ForgedHighTtlDuplicateDoesNotStrandMessage) {
    RouterMesh mesh(3, lineEdges(3));
    ASSERT_TRUE(mesh.ready);

    RoutedMessage genuine = craftBroadcastFrom(*mesh.nodes[0]->identity, { 'o', 'k' });
    genuine.ttlRemaining = 1;                                                                 // TTL ends at node 1
    ASSERT_GT(mesh.nodes[0]->network->sendToPeer(mesh.id(1), RouterWire::encode(genuine)), 0);
    ASSERT_TRUE(waitUntil([&] { return mesh.recorders[1]->countOf(mesh.id(0), genuine.msgId) == 1; }, 5s));

    RoutedMessage forged = genuine;
    forged.ttlInitial   = 255;                                                                // signed field, but duplicates are not verified
    forged.ttlRemaining = 255;
    forged.payload      = { 'x', 'x' };
    ASSERT_GT(mesh.nodes[0]->network->sendToPeer(mesh.id(1), RouterWire::encode(forged)), 0);

    const auto delivered = [&] { return mesh.recorders[2]->find(mesh.id(0), genuine.msgId); };
    ASSERT_TRUE(waitUntil([&] { return delivered().has_value(); }, 5s));
    EXPECT_EQ(delivered()->payload, genuine.payload);                                         // our verified content, not the forger's
    EXPECT_EQ(delivered()->hopsTraveled, 2);
}

// The sender is unknown to node 2. A forgery parked first must not make node 2 drop the genuine copy from the neighbor
// that holds the sender's record.
TEST(RouterTest, ForgedCopyOfUnknownSenderDoesNotBlockGenuineOne) {
    RouterMesh mesh(3, { { 0, 2 }, { 1, 2 } });
    ASSERT_TRUE(mesh.ready);

    const auto sender   = LocalIdentity::generate();
    const auto stranger = LocalIdentity::generate();
    mesh.nodes[1]->directory->upsertPeer(sender.getPeerId(), [&](KnownPeer& kp, bool) { kp.record = makeSignedRecord(sender, { ipv4("192.0.2.9", 7000) }, std::chrono::system_clock::now()); });

    const RoutedMessage forged  = craftBroadcast(sender.getPeerId(), stranger, { 'b', 'a', 'd' });     // same msgId, wrong signer
    const RoutedMessage genuine = craftBroadcast(sender.getPeerId(), sender, { 'g', 'o', 'd' });
    ASSERT_EQ(forged.msgId, genuine.msgId);
    ASSERT_GT(mesh.nodes[0]->network->sendToPeer(mesh.id(2), RouterWire::encode(forged)), 0);
    std::this_thread::sleep_for(100ms);                                                       // parked first
    ASSERT_GT(mesh.nodes[1]->network->sendToPeer(mesh.id(2), RouterWire::encode(genuine)), 0);

    const auto delivered = [&] { return mesh.recorders[2]->find(sender.getPeerId(), genuine.msgId); };
    ASSERT_TRUE(waitUntil([&] { return delivered().has_value(); }, 5s));
    EXPECT_EQ(delivered()->payload, genuine.payload);
}

// A message whose TTL ended here was never announced; a GRAFT for it must not carry it one hop further
TEST(RouterTest, GraftForMessageThatEndedHereIsNotAnswered) {
    RouterMesh mesh(3, lineEdges(3));
    ASSERT_TRUE(mesh.ready);

    RoutedMessage message = craftBroadcastFrom(*mesh.nodes[0]->identity, { 'e', 'n', 'd' });
    message.ttlRemaining = 1;
    ASSERT_GT(mesh.nodes[0]->network->sendToPeer(mesh.id(1), RouterWire::encode(message)), 0);
    ASSERT_TRUE(waitUntil([&] { return mesh.recorders[1]->countOf(mesh.id(0), message.msgId) == 1; }, 5s));

    const std::vector<RoutedMessageKey> keys{ { mesh.id(0), message.msgId } };
    ASSERT_GT(mesh.nodes[2]->network->sendToPeer(mesh.id(1), RouterWire::encodeGraft(keys)), 0);
    std::this_thread::sleep_for(400ms);
    EXPECT_EQ(mesh.recorders[2]->countOf(mesh.id(0), message.msgId), 0u);
    EXPECT_EQ(mesh.routers[1]->getStatistics().fullMessagesSent, 0u);
}

// ── Routes learned from traffic (R-5 a) ─────────────────────────────────────

TEST(RouterTest, BroadcastTeachesRouteToItsSenderAndDisconnectEndsIt) {
    RouterMesh mesh(4, lineEdges(4));
    ASSERT_TRUE(mesh.ready);

    const uint64_t msgId = mesh.routers[0]->broadcast(0x10, 0, { 'r' }).value();
    ASSERT_TRUE(waitUntil([&] { return mesh.allOthersDelivered(0, msgId); }, 5s));

    for (size_t i = 1; i < 4; ++i) {
        const auto candidates = mesh.routers[i]->getRouteCandidates(mesh.id(0));
        ASSERT_EQ(candidates.size(), 1u) << "node " << i;
        EXPECT_EQ(candidates.front().via, mesh.id(i - 1));                                    // back the way it came
        EXPECT_EQ(candidates.front().hops, i);
        EXPECT_EQ(candidates.front().evidence, RouteEvidence::Broadcast);
    }
    EXPECT_TRUE(mesh.routers[0]->getRouteCandidates(mesh.id(0)).empty());                     // no route to ourselves

    mesh.routers[2]->stop();
    mesh.nodes[2]->network->stop();
    EXPECT_TRUE(waitUntil([&] { return mesh.routers[3]->getRouteCandidates(mesh.id(0)).empty(); }, 5s));   // its only neighbor left
    EXPECT_EQ(mesh.routers[1]->getRouteCandidates(mesh.id(0)).size(), 1u);                    // not through node 2: unaffected
}

// ── UNICAST (R-5 b) ─────────────────────────────────────────────────────────

namespace {
RoutedMessage craftUnicast(const PeerId& claimedSender, const PeerId& destination, std::vector<uint8_t> payload) {
    RoutedMessage m;
    m.group             = 0x10;
    m.subtype           = 0x0002;
    m.mode              = RoutingMode::Unicast;
    m.ttlInitial        = 16;
    m.ttlRemaining      = 16;
    m.msgId             = 0xC0DE0000ULL + payload.size();
    m.sentAtUnixSeconds = static_cast<uint32_t>(std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count());
    m.sender            = claimedSender;
    m.destination       = destination;
    m.payload           = std::move(payload);
    return m;
}
}

// The destination's broadcast taught every node the way back: the message follows it, no flooding
TEST(RouterTest, UnicastFollowsLearnedRouteToEndOfLine) {
    RouterMesh mesh(5, lineEdges(5));
    ASSERT_TRUE(mesh.ready);
    const uint64_t hello = mesh.routers[4]->broadcast(0x10, 0, { 'h' }).value();
    ASSERT_TRUE(waitUntil([&] { return mesh.allOthersDelivered(4, hello); }, 5s));
    std::this_thread::sleep_for(200ms);
    const uint64_t before = totalFullMessagesSent(mesh);

    const uint64_t msgId = mesh.routers[0]->send(mesh.id(4), 0x10, 7, { 'u', 'n', 'i' }).value();
    ASSERT_TRUE(waitUntil([&] { return mesh.recorders[4]->countOf(mesh.id(0), msgId) == 1; }, 5s));
    std::this_thread::sleep_for(200ms);

    const auto delivery = mesh.recorders[4]->find(mesh.id(0), msgId);
    EXPECT_EQ(delivery->mode, RoutingMode::Unicast);
    EXPECT_EQ(delivery->hopsTraveled, 4);
    EXPECT_EQ(delivery->subtype, 7);
    EXPECT_FALSE(delivery->senderAuthenticated);                                              // relayed: the sender is only claimed
    EXPECT_EQ(totalFullMessagesSent(mesh) - before, 4u);                                      // one copy per hop
    for (size_t i = 0; i < 5; ++i) EXPECT_EQ(mesh.routers[i]->getStatistics().localFloods, 0u) << "node " << i;
    for (size_t i = 1; i < 4; ++i) EXPECT_EQ(mesh.recorders[i]->countOf(mesh.id(0), msgId), 0u);   // relays do not deliver
}

// Nobody knows the destination: local flooding finds it, and it is delivered exactly once
TEST(RouterTest, UnicastWithoutRouteFloodsLocallyAndArrivesOnce) {
    RouterMesh mesh(8, ringWithChords());
    ASSERT_TRUE(mesh.ready);

    const uint64_t msgId = mesh.routers[0]->send(mesh.id(6), 0x10, 0, { 'f' }).value();
    ASSERT_TRUE(waitUntil([&] { return mesh.recorders[6]->countOf(mesh.id(0), msgId) == 1; }, 5s));
    std::this_thread::sleep_for(300ms);
    EXPECT_EQ(mesh.recorders[6]->countOf(mesh.id(0), msgId), 1u);
    EXPECT_GT(mesh.routers[0]->getStatistics().localFloods, 0u);
    for (size_t i = 0; i < 8; ++i) if (i != 6) { EXPECT_EQ(mesh.recorders[i]->total(), 0u) << "node " << i; }
}

TEST(RouterTest, UnicastFromNeighborHasAuthenticatedSenderOthersDoNot) {
    RouterMesh mesh(2, lineEdges(2));
    ASSERT_TRUE(mesh.ready);

    const uint64_t direct = mesh.routers[0]->send(mesh.id(1), 0x10, 0, { 'd' }).value();
    ASSERT_TRUE(waitUntil([&] { return mesh.recorders[1]->countOf(mesh.id(0), direct) == 1; }, 5s));
    const auto delivery = mesh.recorders[1]->find(mesh.id(0), direct);
    EXPECT_TRUE(delivery->senderAuthenticated);
    EXPECT_EQ(delivery->hopsTraveled, 1);

    // Node 0 claims someone else sent it: delivered, but not as authenticated
    const auto stranger = LocalIdentity::generate();
    const RoutedMessage claimed = craftUnicast(stranger.getPeerId(), mesh.id(1), { 'c', 'l' });
    ASSERT_GT(mesh.nodes[0]->network->sendToPeer(mesh.id(1), RouterWire::encode(claimed)), 0);
    ASSERT_TRUE(waitUntil([&] { return mesh.recorders[1]->countOf(stranger.getPeerId(), claimed.msgId) == 1; }, 5s));
    EXPECT_FALSE(mesh.recorders[1]->find(stranger.getPeerId(), claimed.msgId)->senderAuthenticated);
}

TEST(RouterTest, UnicastTtlLimitsHowFarItTravels) {
    RouterMesh mesh(4, lineEdges(4), [](size_t i, RouterConfig& c) { if (i == 0) c.unicastTtl = 2; });
    ASSERT_TRUE(mesh.ready);
    const uint64_t far  = mesh.routers[0]->send(mesh.id(3), 0x10, 0, { 'x' }).value();
    const uint64_t near = mesh.routers[0]->send(mesh.id(2), 0x10, 0, { 'y' }).value();
    ASSERT_TRUE(waitUntil([&] { return mesh.recorders[2]->countOf(mesh.id(0), near) == 1; }, 5s));
    std::this_thread::sleep_for(300ms);
    EXPECT_EQ(mesh.recorders[3]->countOf(mesh.id(0), far), 0u);
}

TEST(RouterTest, SendRefusesOwnNodeAndNonUserGroups) {
    RouterMesh mesh(2, lineEdges(2));
    ASSERT_TRUE(mesh.ready);
    EXPECT_FALSE(mesh.routers[0]->send(mesh.id(0), 0x10, 0, { 1 }).has_value());
    EXPECT_FALSE(mesh.routers[0]->send(mesh.id(1), RouterWire::ROUTER_PROTOCOL_GROUP, 0, { 1 }).has_value());
    mesh.routers[0]->stop();
    EXPECT_FALSE(mesh.routers[0]->send(mesh.id(1), 0x10, 0, { 1 }).has_value());
}
