#include <gtest/gtest.h>
#include "meshlink/route_table.h"

using namespace invilite::Mesh;
using namespace std::chrono_literals;

namespace {

const auto T0 = std::chrono::steady_clock::time_point(std::chrono::seconds(1000));

PeerId peerId(uint8_t fill) { PeerId id; id.fill(fill); return id; }

const PeerId DEST = peerId(0xD0), A = peerId(0xA), B = peerId(0xB), C = peerId(0xC), E = peerId(0xE);

} // namespace

TEST(RouteTableTest, LearnsFromBroadcastsAndRanksByHops) {
    RouteTable table;
    EXPECT_TRUE(table.nextHops(DEST).empty());
    table.learn(DEST, A, 4, T0);
    table.learn(DEST, B, 2, T0 + 1s);
    table.learn(DEST, C, 3, T0 + 2s);
    EXPECT_EQ(table.nextHops(DEST), (std::vector<PeerId>{ B, C, A }));
    EXPECT_EQ(table.nextHops(DEST, B), (std::vector<PeerId>{ C, A }));                       // not back where it came from
}

// docs/router.md 4.4a: measured (by RTT) before delivered before hinted (by hops) — fewer hops do not beat a measurement
TEST(RouteTableTest, MeasuredBeforeDeliveredBeforeHinted) {
    RouteTable table;
    table.learn(DEST, A, 1, T0);
    table.learn(DEST, B, 4, T0);
    table.learn(DEST, C, 6, T0);
    EXPECT_EQ(table.nextHops(DEST), (std::vector<PeerId>{ A, B, C }));

    table.recordDelivery(DEST, C, T0 + 1s);
    EXPECT_EQ(table.nextHops(DEST), (std::vector<PeerId>{ C, A, B }));
    EXPECT_EQ(table.candidates(DEST).front().tier(), RouteTier::Delivered);

    table.recordMeasurement(DEST, B, 4, 80ms, T0 + 2s);
    EXPECT_EQ(table.nextHops(DEST), (std::vector<PeerId>{ B, C, A }));
    EXPECT_EQ(table.candidates(DEST).front().tier(), RouteTier::Measured);
}

TEST(RouteTableTest, MeasurementsAreSmoothedAndOrderedByRtt) {
    RouteTable table;
    table.recordMeasurement(DEST, A, 3, 100ms, T0);
    table.recordMeasurement(DEST, A, 3, 20ms, T0 + 1s);
    EXPECT_EQ(table.candidates(DEST).front().rtt, 80ms);                                     // (3 × 100 + 20) / 4
    table.recordMeasurement(DEST, B, 5, 50ms, T0 + 2s);
    EXPECT_EQ(table.nextHops(DEST), (std::vector<PeerId>{ B, A }));                          // faster wins over fewer hops
}

// A failure drops the candidate to the last tier; a success restores it; failuresToForget in a row remove it
TEST(RouteTableTest, FailuresDemoteAndThreeInARowRemove) {
    RouteTable table;
    table.recordMeasurement(DEST, A, 2, 30ms, T0);
    table.learn(DEST, B, 5, T0);
    table.recordFailure(DEST, A);
    EXPECT_EQ(table.nextHops(DEST), (std::vector<PeerId>{ B, A }));
    EXPECT_EQ(table.candidates(DEST).back().tier(), RouteTier::Failing);

    table.recordMeasurement(DEST, A, 2, 30ms, T0 + 1s);                                       // works again
    EXPECT_EQ(table.nextHops(DEST), (std::vector<PeerId>{ A, B }));
    EXPECT_EQ(table.candidates(DEST).front().failures, 0);

    for (int i = 0; i < 3; ++i) table.recordFailure(DEST, A);
    EXPECT_EQ(table.nextHops(DEST), (std::vector<PeerId>{ B }));
    for (int i = 0; i < 3; ++i) table.recordFailure(DEST, B);
    EXPECT_EQ(table.destinationCount(), 0u);
}

// A delivery through a neighbor we never heard the destination behind says nothing usable — except the destination
// itself, a direct neighbor
TEST(RouteTableTest, DeliveryAddsOnlyTheDestinationItself) {
    RouteTable table;
    table.recordDelivery(DEST, A, T0);
    EXPECT_EQ(table.destinationCount(), 0u);
    table.recordDelivery(DEST, DEST, T0);
    ASSERT_EQ(table.candidates(DEST).size(), 1u);
    EXPECT_EQ(table.candidates(DEST).front().hops, 1);
    EXPECT_EQ(table.candidates(DEST).front().deliveries, 1u);
}

// Routes do not expire: an hour later the route is still there
TEST(RouteTableTest, RoutesDoNotExpireWithTime) {
    RouteTable table;
    table.learn(DEST, A, 2, T0);
    table.learn(peerId(0xD1), B, 1, T0 + 1h);
    EXPECT_EQ(table.nextHops(DEST), (std::vector<PeerId>{ A }));
}

TEST(RouteTableTest, KeepsTheBestCandidatesOnly) {
    RouteTable table(RouteTableConfig{ .candidatesPerDestination = 2, .maxDestinations = 10 });
    table.learn(DEST, A, 3, T0);
    table.learn(DEST, B, 2, T0);
    table.learn(DEST, C, 5, T0);                                    // worse than both: not kept
    EXPECT_EQ(table.nextHops(DEST), (std::vector<PeerId>{ B, A }));
    table.learn(DEST, E, 1, T0);                                    // better: the worst goes
    EXPECT_EQ(table.nextHops(DEST), (std::vector<PeerId>{ E, B }));
}

TEST(RouteTableTest, DisconnectedNeighborTakesItsRoutesAlong) {
    RouteTable table;
    table.learn(DEST, A, 2, T0);
    table.learn(DEST, B, 3, T0);
    table.learn(peerId(0xD1), A, 1, T0);
    table.forgetNeighbor(A);
    EXPECT_EQ(table.nextHops(DEST), (std::vector<PeerId>{ B }));
    EXPECT_TRUE(table.nextHops(peerId(0xD1)).empty());
    EXPECT_EQ(table.destinationCount(), 1u);

    table.forgetRoute(DEST, B);
    EXPECT_EQ(table.destinationCount(), 0u);
}

TEST(RouteTableTest, FullTableDropsTheLeastRecentlyHeardDestination) {
    RouteTable table(RouteTableConfig{ .candidatesPerDestination = 3, .maxDestinations = 2 });
    table.learn(peerId(1), A, 1, T0);
    table.learn(peerId(2), A, 1, T0);
    table.learn(peerId(1), B, 2, T0 + 1s);                         // 1 heard again: 2 is now the oldest
    table.learn(peerId(3), A, 1, T0 + 2s);
    EXPECT_EQ(table.destinationCount(), 2u);
    EXPECT_TRUE(table.nextHops(peerId(2)).empty());
    EXPECT_FALSE(table.nextHops(peerId(1)).empty());
    EXPECT_FALSE(table.nextHops(peerId(3)).empty());
}

// Review R-5 M1: a hint's hop count is unsigned (a relay can lower it); it must not rewrite what a probe recorded
TEST(RouteTableTest, HintDoesNotRewriteHopsOfMeasuredRoute) {
    RouteTable table;
    table.recordMeasurement(DEST, A, 3, 40ms, T0);
    table.learn(DEST, A, 1, T0 + 1s);
    const auto candidates = table.candidates(DEST);
    ASSERT_EQ(candidates.size(), 1u);
    EXPECT_EQ(candidates[0].hops, 3);
    EXPECT_EQ(candidates[0].tier(), RouteTier::Measured);
    EXPECT_EQ(candidates[0].lastHeardAt, T0 + 1s);

    table.recordMeasurement(DEST, A, 2, 40ms, T0 + 2s);                                        // a newer probe does update it
    EXPECT_EQ(table.candidates(DEST)[0].hops, 2);
}

// Diagnostics page through the table in PeerId order: consecutive pages cover every destination exactly once
TEST(RouteTableTest, DestinationPagesAreOrderedAndCoverTheTable) {
    RouteTable table;
    for (uint8_t fill : { 0x50, 0x10, 0x30, 0x40, 0x20 }) table.learn(peerId(fill), A, 2, T0);
    table.learn(peerId(0x30), B, 3, T0);

    const auto first = table.destinationsPage(0, 2);
    const auto second = table.destinationsPage(2, 2);
    const auto last = table.destinationsPage(4, 2);
    ASSERT_EQ(first.size(), 2u);
    ASSERT_EQ(second.size(), 2u);
    ASSERT_EQ(last.size(), 1u);
    EXPECT_EQ(first[0].first, peerId(0x10));
    EXPECT_EQ(first[1].first, peerId(0x20));
    EXPECT_EQ(second[0].first, peerId(0x30));
    EXPECT_EQ(second[0].second.size(), 2u);                                                   // every candidate, best first
    EXPECT_EQ(second[0].second[0].via, A);
    EXPECT_EQ(last[0].first, peerId(0x50));
    EXPECT_TRUE(table.destinationsPage(5, 2).empty());
}
