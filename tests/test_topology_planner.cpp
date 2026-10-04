#include <gtest/gtest.h>
#include "meshlink/network.h"
#include "meshlink/topology_planner.h"
#include "test_helpers.h"

using namespace invilite::Mesh;
using namespace invilite::Mesh::TestHelpers;
using namespace std::chrono_literals;

namespace {

PeerId peerIdOf(uint8_t tag) {
    PeerId id{};
    id[0] = tag;
    return id;
}

std::vector<ConnectedPeerInfo> outboundPeers(size_t count) {
    std::vector<ConnectedPeerInfo> peers;
    for (size_t i = 0; i < count; ++i) peers.push_back({ peerIdOf(static_cast<uint8_t>(i + 1)), true });
    return peers;
}

std::vector<ConnectedPeerInfo> mixedPeers(size_t inbound, size_t outbound) {
    std::vector<ConnectedPeerInfo> peers;
    for (size_t i = 0; i < inbound + outbound; ++i) peers.push_back({ peerIdOf(static_cast<uint8_t>(i + 1)), i >= inbound });
    return peers;
}

SignedPeerRecord candidateAt(const char* address, uint16_t port) {
    SignedPeerRecord record;
    record.addresses = { ipv4(address, port) };
    return record;
}

} // namespace

TEST(TopologyPlannerTest, DialsCandidateWhenBelowOutboundTarget) {
    NetworkConfig config;
    config.connectionLimits.outbound = { .min = 0, .soft = 2, .hard = {} };

    const auto candidate = candidateAt("192.0.2.10", 5000);
    const auto decision  = TopologyPlanner{}.evaluate(outboundPeers(1), { candidate }, config);

    ASSERT_TRUE(decision.connectTo.has_value());
    EXPECT_EQ(decision.connectTo->peerId, candidate.peerId);                                 // the caller tracks the attempt per peer (R9)
    EXPECT_EQ(decision.connectTo->address, "192.0.2.10");
    EXPECT_EQ(decision.connectTo->port, 5000);
    EXPECT_EQ(decision.nextTick, 3s);
}

TEST(TopologyPlannerTest, WaitsLongerWhenBelowTargetWithoutCandidates) {
    NetworkConfig config;
    config.connectionLimits.outbound = { .min = 0, .soft = 2, .hard = {} };

    const auto decision = TopologyPlanner{}.evaluate(outboundPeers(1), {}, config);

    EXPECT_FALSE(decision.connectTo.has_value());
    EXPECT_EQ(decision.nextTick, 10s);
}

TEST(TopologyPlannerTest, DoesNothingWhenOutboundTargetReached) {
    NetworkConfig config;
    config.connectionLimits.outbound = { .min = 0, .soft = 2, .hard = {} };

    const auto decision = TopologyPlanner{}.evaluate(outboundPeers(2), { candidateAt("192.0.2.10", 5000) }, config);

    EXPECT_FALSE(decision.connectTo.has_value());
    EXPECT_EQ(decision.nextTick, 30s);
}

TEST(TopologyPlannerTest, InboundPeersDoNotCountTowardsOutboundTarget) {
    NetworkConfig config;
    config.connectionLimits.outbound = { .min = 0, .soft = 1, .hard = {} };
    const std::vector<ConnectedPeerInfo> inboundOnly = { { peerIdOf(1), false }, { peerIdOf(2), false } };

    const auto decision = TopologyPlanner{}.evaluate(inboundOnly, { candidateAt("192.0.2.10", 5000) }, config);

    EXPECT_TRUE(decision.connectTo.has_value());
}

TEST(TopologyPlannerTest, NeverRequestsDisconnectYet) {
    NetworkConfig config;
    config.connectionLimits.outbound = { .min = 0, .soft = 1, .hard = {} };

    const auto decision = TopologyPlanner{}.evaluate(outboundPeers(5), { candidateAt("192.0.2.10", 5000) }, config);

    EXPECT_FALSE(decision.disconnect.has_value());
}

// R10: the outbound target is what inbound does not cover of the healthy total, clamped to [min, soft].
// A public node with plenty of inbound needs only the minimum of self-chosen outbound connections.
TEST(TopologyPlannerTest, PublicNodeWithManyInboundKeepsOnlyMinimumOutbound) {
    NetworkConfig config;
    config.connectionLimits.total    = 24;
    config.connectionLimits.outbound = { .min = 2, .soft = 12, .hard = {} };
    const std::vector<SignedPeerRecord> candidates = { candidateAt("192.0.2.10", 5000) };

    EXPECT_TRUE(TopologyPlanner{}.evaluate(mixedPeers(22, 1), candidates, config).connectTo.has_value());
    EXPECT_FALSE(TopologyPlanner{}.evaluate(mixedPeers(22, 2), candidates, config).connectTo.has_value());
}

// ...a node nobody can reach (behind NAT, no inbound) fills up to soft by itself...
TEST(TopologyPlannerTest, NodeWithoutInboundDialsUpToSoftLimit) {
    NetworkConfig config;
    config.connectionLimits.total    = 24;
    config.connectionLimits.outbound = { .min = 2, .soft = 12, .hard = {} };
    const std::vector<SignedPeerRecord> candidates = { candidateAt("192.0.2.10", 5000) };

    EXPECT_TRUE(TopologyPlanner{}.evaluate(outboundPeers(11), candidates, config).connectTo.has_value());
    EXPECT_FALSE(TopologyPlanner{}.evaluate(outboundPeers(12), candidates, config).connectTo.has_value());
}

// ...and inbound above the total never pushes the target below min — an attacker filling our inbound slots must not
// leave us with only connections it chose (eclipse).
TEST(TopologyPlannerTest, InboundAboveTotalStillKeepsMinimumOutbound) {
    NetworkConfig config;
    config.connectionLimits.total    = 24;
    config.connectionLimits.outbound = { .min = 2, .soft = 12, .hard = {} };

    EXPECT_TRUE(TopologyPlanner{}.evaluate(mixedPeers(30, 1), { candidateAt("192.0.2.10", 5000) }, config).connectTo.has_value());
}
