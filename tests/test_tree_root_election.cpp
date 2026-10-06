#include <gtest/gtest.h>
#include "meshlink/tree_root_election.h"

using namespace invilite::Mesh;
using namespace std::chrono_literals;

namespace {

const auto T0 = std::chrono::steady_clock::time_point(std::chrono::seconds(1000));

PeerId peerId(uint8_t fill) { PeerId id; id.fill(fill); return id; }

const PeerId SMALL = peerId(0x10), SELF = peerId(0x50), LARGE = peerId(0x90);

TreeRootConfig config() { return { true, 30s, 3 }; }

using Kind = TreeRootChange::Kind;

} // namespace

TEST(TreeRootElectionTest, LoneNodeClaimsAfterListeningAndBeaconsEveryInterval) {
    TreeRootElection election(SELF, config());
    election.start(T0, 40s);
    EXPECT_FALSE(election.root().has_value());
    EXPECT_FALSE(election.tick(T0 + 39s, 40s).sendBeacon);

    const auto claim = election.tick(T0 + 40s, 40s);
    ASSERT_EQ(claim.changes.size(), 1u);
    EXPECT_EQ(claim.changes[0].kind, Kind::Claimed);
    EXPECT_TRUE(claim.sendBeacon);
    EXPECT_TRUE(election.isRoot());
    EXPECT_EQ(election.root(), SELF);

    EXPECT_FALSE(election.tick(T0 + 69s, 40s).sendBeacon);
    EXPECT_TRUE(election.tick(T0 + 70s, 40s).sendBeacon);
    EXPECT_EQ(election.nextDeadline(), T0 + 100s);
}

TEST(TreeRootElectionTest, SmallerBeaconWhileListeningIsAdoptedAndNothingIsClaimed) {
    TreeRootElection election(SELF, config());
    election.start(T0, 40s);
    const auto changes = election.onBeacon(SMALL, T0 + 5s);
    ASSERT_EQ(changes.size(), 1u);
    EXPECT_EQ(changes[0].kind, Kind::Adopted);
    EXPECT_EQ(changes[0].root, SMALL);
    EXPECT_FALSE(changes[0].previous.has_value());

    for (auto t = 10s; t <= 60s; t += 10s) {
        election.onBeacon(SMALL, T0 + t);                                                     // keeps beaconing
        EXPECT_TRUE(election.tick(T0 + t, 40s).changes.empty());
    }
    EXPECT_FALSE(election.isRoot());
    EXPECT_EQ(election.root(), SMALL);
}

// A larger root is followed until this node, being smaller, has listened long enough — then it takes over
TEST(TreeRootElectionTest, LargerRootIsFollowedUntilThisNodeClaims) {
    TreeRootElection election(SELF, config());
    election.start(T0, 40s);
    election.onBeacon(LARGE, T0 + 5s);
    EXPECT_EQ(election.root(), LARGE);
    EXPECT_TRUE(election.tick(T0 + 20s, 40s).changes.empty());

    const auto claim = election.tick(T0 + 40s, 40s);
    ASSERT_EQ(claim.changes.size(), 1u);
    EXPECT_EQ(claim.changes[0].kind, Kind::Claimed);
    EXPECT_EQ(claim.changes[0].previous, LARGE);
    EXPECT_EQ(election.root(), SELF);
    EXPECT_TRUE(election.onBeacon(LARGE, T0 + 45s).empty());                                 // it will yield once it hears us
    EXPECT_EQ(election.root(), SELF);
}

TEST(TreeRootElectionTest, RootYieldsToSmallerBeacon) {
    TreeRootElection election(SELF, config());
    election.start(T0, 1s);
    ASSERT_TRUE(election.tick(T0 + 1s, 1s).sendBeacon);

    const auto changes = election.onBeacon(SMALL, T0 + 2s);
    ASSERT_EQ(changes.size(), 1u);
    EXPECT_EQ(changes[0].kind, Kind::Yielded);
    EXPECT_EQ(changes[0].root, SMALL);
    EXPECT_FALSE(election.isRoot());
    EXPECT_FALSE(election.tick(T0 + 40s, 1s).sendBeacon);                                    // no beacons any more
}

TEST(TreeRootElectionTest, SmallerRootReplacesHeardOne) {
    TreeRootElection follower(LARGE, config());
    follower.start(T0, 40s);
    follower.onBeacon(SELF, T0 + 1s);
    const auto changes = follower.onBeacon(SMALL, T0 + 2s);
    ASSERT_EQ(changes.size(), 1u);
    EXPECT_EQ(changes[0].root, SMALL);
    EXPECT_EQ(changes[0].previous, SELF);
    EXPECT_TRUE(follower.onBeacon(SELF, T0 + 3s).empty());                                   // the larger one no longer counts
    EXPECT_EQ(follower.root(), SMALL);
}

// Three missed beacons: the root is forgotten, and after listening again the node claims (nobody smaller is heard)
TEST(TreeRootElectionTest, SilentRootIsLostThenNextSmallestClaims) {
    TreeRootElection election(SELF, config());
    election.start(T0, 40s);
    election.onBeacon(SMALL, T0 + 1s);
    EXPECT_TRUE(election.tick(T0 + 90s, 20s).changes.empty());

    const auto lost = election.tick(T0 + 91s, 20s);
    ASSERT_EQ(lost.changes.size(), 1u);
    EXPECT_EQ(lost.changes[0].kind, Kind::Lost);
    EXPECT_EQ(lost.changes[0].previous, SMALL);
    EXPECT_FALSE(election.root().has_value());
    EXPECT_FALSE(lost.sendBeacon);

    EXPECT_FALSE(election.tick(T0 + 110s, 20s).sendBeacon);
    const auto claim = election.tick(T0 + 111s, 20s);
    ASSERT_EQ(claim.changes.size(), 1u);
    EXPECT_EQ(claim.changes[0].kind, Kind::Claimed);
}

TEST(TreeRootElectionTest, OwnBeaconAndBeaconsBeforeStartAreIgnored) {
    TreeRootElection election(SELF, config());
    EXPECT_TRUE(election.onBeacon(SMALL, T0).empty());                                       // not started
    election.start(T0, 40s);
    EXPECT_TRUE(election.onBeacon(SELF, T0 + 1s).empty());
    EXPECT_FALSE(election.root().has_value());
}
