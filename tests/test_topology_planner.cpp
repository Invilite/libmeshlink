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

SignedPeerRecord candidateAt(const char* address, uint16_t port) {
    SignedPeerRecord record;
    record.addresses = { ipv4(address, port) };
    return record;
}

} // namespace

TEST(TopologyPlannerTest, DialsCandidateWhenBelowOutboundTarget) {
    NetworkConfig config;
    config.targetOutbound = 2;

    const auto decision = TopologyPlanner{}.evaluate(outboundPeers(1), { candidateAt("192.0.2.10", 5000) }, config);

    ASSERT_TRUE(decision.connectTo.has_value());
    EXPECT_EQ(decision.connectTo->first, "192.0.2.10");
    EXPECT_EQ(decision.connectTo->second, 5000);
    EXPECT_EQ(decision.nextTick, 3s);
}

TEST(TopologyPlannerTest, WaitsLongerWhenBelowTargetWithoutCandidates) {
    NetworkConfig config;
    config.targetOutbound = 2;

    const auto decision = TopologyPlanner{}.evaluate(outboundPeers(1), {}, config);

    EXPECT_FALSE(decision.connectTo.has_value());
    EXPECT_EQ(decision.nextTick, 10s);
}

TEST(TopologyPlannerTest, DoesNothingWhenOutboundTargetReached) {
    NetworkConfig config;
    config.targetOutbound = 2;

    const auto decision = TopologyPlanner{}.evaluate(outboundPeers(2), { candidateAt("192.0.2.10", 5000) }, config);

    EXPECT_FALSE(decision.connectTo.has_value());
    EXPECT_EQ(decision.nextTick, 30s);
}

TEST(TopologyPlannerTest, InboundPeersDoNotCountTowardsOutboundTarget) {
    NetworkConfig config;
    config.targetOutbound = 1;
    const std::vector<ConnectedPeerInfo> inboundOnly = { { peerIdOf(1), false }, { peerIdOf(2), false } };

    const auto decision = TopologyPlanner{}.evaluate(inboundOnly, { candidateAt("192.0.2.10", 5000) }, config);

    EXPECT_TRUE(decision.connectTo.has_value());
}

TEST(TopologyPlannerTest, NeverRequestsDisconnectYet) {
    NetworkConfig config;
    config.targetOutbound = 1;

    const auto decision = TopologyPlanner{}.evaluate(outboundPeers(5), { candidateAt("192.0.2.10", 5000) }, config);

    EXPECT_FALSE(decision.disconnect.has_value());
}
