// SIM (docs/router.md 6): Plumtree in larger meshes with one and several senders at once. The eager/lazy state is per
// link, shared by every sender: with one sender it settles to a spanning tree (N − 1 full copies); several senders need
// oscillating links pinned (below). Real Network instances over loopback: there is no link latency, so the
// latency-driven tree optimization is not exercised here.
// Network and Router log to stderr; run `./run_test 2>/dev/null` for quiet output.
#include <gtest/gtest.h>
#include "router_test_mesh.h"

#include <iostream>
#include <random>
#include <set>

using namespace invilite::Mesh;
using namespace invilite::Mesh::TestHelpers;
using namespace std::chrono_literals;

namespace {

constexpr size_t NODES   = 30;
constexpr size_t MANY_SENDERS = 5;
// Rounds per run: several senders settle more slowly, the more so under load (pins only accumulate, so they do settle)
constexpr size_t ROUNDS_ONE_SENDER   = 8;
constexpr size_t ROUNDS_MANY_SENDERS = 16;
constexpr size_t SETTLED_ROUNDS = 2;                                                          // the last rounds are checked

// Every edge once, as (dialer, listener) with dialer < listener
void addEdge(std::set<std::pair<size_t, size_t>>& edges, size_t a, size_t b) {
    if (a != b) edges.insert({ std::min(a, b), std::max(a, b) });
}

std::vector<Edge> toEdges(const std::set<std::pair<size_t, size_t>>& edges) { return { edges.begin(), edges.end() }; }

// A ring (connected) with random chords: average degree about 4
std::vector<Edge> randomMesh(size_t count, uint32_t seed) {
    std::mt19937 random(seed);
    std::set<std::pair<size_t, size_t>> edges;
    for (size_t i = 0; i < count; ++i) addEdge(edges, i, (i + 1) % count);
    std::uniform_int_distribution<size_t> pick(0, count - 1);
    while (edges.size() < 2 * count) addEdge(edges, pick(random), pick(random));
    return toEdges(edges);
}

// Each node linked to its two nearest ring neighbors on either side, a few links rewired to random far nodes
std::vector<Edge> smallWorld(size_t count, uint32_t seed) {
    std::mt19937 random(seed);
    std::set<std::pair<size_t, size_t>> edges;
    std::uniform_int_distribution<size_t> pick(0, count - 1);
    std::bernoulli_distribution rewire(0.1);
    for (size_t i = 0; i < count; ++i) {
        addEdge(edges, i, (i + 1) % count);
        addEdge(edges, i, rewire(random) ? pick(random) : (i + 2) % count);
    }
    return toEdges(edges);
}

// Two random halves joined by a single bridge: every message from one half to the other crosses one link
std::vector<Edge> twoClustersWithBridge(size_t count, uint32_t seed) {
    std::mt19937 random(seed);
    std::set<std::pair<size_t, size_t>> edges;
    const size_t half = count / 2;
    for (const auto& [first, size] : { std::pair{ size_t{ 0 }, half }, std::pair{ half, count - half } }) {
        std::uniform_int_distribution<size_t> pick(first, first + size - 1);
        for (size_t i = 0; i < size; ++i) addEdge(edges, first + i, first + (i + 1) % size);
        const size_t target = edges.size() + size;
        while (edges.size() < target) addEdge(edges, pick(random), pick(random));
    }
    addEdge(edges, 0, half);
    return toEdges(edges);
}

struct RoundCost {
    uint64_t fullCopies = 0;
    uint64_t announcedKeys = 0;
    uint64_t grafts = 0;
    uint64_t prunes = 0;
    uint64_t graftsForMissing = 0;                                                            // the rest are tree optimization (no link went down)
    uint64_t pinnedLinkEnds = 0;                                                              // at the end of the round; each link counts at both ends
};

RoundCost totals(const RouterMesh& mesh) {
    RoundCost cost;
    for (const auto& router : mesh.routers) {
        const RouterStatistics stats = router->getStatistics();
        cost.fullCopies    += stats.fullMessagesSent;
        cost.announcedKeys += stats.announcementsSent;
        cost.grafts        += stats.graftsSent;
        cost.prunes        += stats.prunesSent;
        cost.graftsForMissing += stats.graftsForMissing;
        cost.pinnedLinkEnds   += stats.pinnedLinks;
    }
    return cost;
}

// Rounds of simultaneous broadcasts, one per sender; every message must reach every other node exactly once. Returns each round's cost.
std::vector<RoundCost> runRounds(RouterMesh& mesh, const std::string& topology, size_t senderCount) {
    std::vector<size_t> senders;
    for (size_t i = 0; i < senderCount; ++i) senders.push_back(i * NODES / senderCount);

    std::vector<RoundCost> rounds;
    const size_t roundCount = senderCount == 1 ? ROUNDS_ONE_SENDER : ROUNDS_MANY_SENDERS;
    for (size_t round = 0; round < roundCount; ++round) {
        const RoundCost before = totals(mesh);
        std::vector<std::pair<size_t, uint64_t>> sent;
        for (size_t sender : senders) sent.emplace_back(sender, mesh.routers[sender]->broadcast(0x10, 0, { static_cast<uint8_t>(round) }).value());
        for (const auto& [sender, msgId] : sent) {
            EXPECT_TRUE(waitUntil([&] { return mesh.allOthersDelivered(sender, msgId); }, 10s)) << topology << ": round " << round << ", sender " << sender;
        }
        std::this_thread::sleep_for(700ms);                                                    // IHAVE batches, GRAFT timers, PRUNEs settle
        for (const auto& [sender, msgId] : sent) {
            for (size_t node = 0; node < NODES; ++node) {
                if (node == sender) continue;
                EXPECT_EQ(mesh.recorders[node]->countOf(mesh.id(sender), msgId), 1u) << topology << ": round " << round << ", node " << node;
            }
        }
        const RoundCost after = totals(mesh);
        rounds.push_back({ after.fullCopies - before.fullCopies, after.announcedKeys - before.announcedKeys, after.grafts - before.grafts, after.prunes - before.prunes, after.graftsForMissing - before.graftsForMissing, after.pinnedLinkEnds });
    }

    std::cout << "[ SIM      ] " << topology << " (" << NODES << " nodes, " << senderCount << " sender(s)): full copies / IHAVE keys / GRAFT (for missing) / PRUNE / pinned links per round:";
    for (const RoundCost& cost : rounds) std::cout << "  " << cost.fullCopies << "/" << cost.announcedKeys << "/" << cost.grafts << " (" << cost.graftsForMissing << ")/" << cost.prunes << "/" << cost.pinnedLinkEnds / 2;
    std::cout << "  (a tree: " << senderCount * (NODES - 1) << " full copies, a flood: " << senderCount * (2 * mesh.edgeCount - (NODES - 1)) << ")" << std::endl;
    return rounds;
}

// One sender: exactly a spanning tree, nothing changes any more. Several: what matters is that nobody waits for a GRAFT
// any more (no GRAFT for a missing message); pinned links cost extra copies — 0–50 % over a tree in SIM runs, depending
// on how the first rounds went — bounded here at twice a tree, still well below a flood (about 3× a tree here).
void expectSettledTree(const std::vector<RoundCost>& rounds, const std::string& topology, size_t senderCount) {
    const uint64_t tree = senderCount * (NODES - 1);
    for (size_t round = rounds.size() - SETTLED_ROUNDS; round < rounds.size(); ++round) {
        EXPECT_EQ(rounds[round].graftsForMissing, 0u) << topology << ": round " << round;
        if (senderCount > 1) {
            EXPECT_LE(rounds[round].fullCopies, 2 * tree) << topology << ": round " << round;
            continue;
        }
        EXPECT_EQ(rounds[round].fullCopies, tree) << topology << ": round " << round << " is not a spanning tree";
        EXPECT_EQ(rounds[round].grafts, 0u) << topology << ": round " << round;
        EXPECT_EQ(rounds[round].prunes, 0u) << topology << ": round " << round;
    }
}

void simulate(const std::string& topology, const std::vector<Edge>& edges, size_t senderCount) {
    // Every connection comes from 127.0.0.1: the per-address inbound limit (5) would refuse well-connected nodes
    RouterMesh mesh(NODES, edges, {}, [](NetworkConfig& config) { config.connectionLimits.inbound.perAddress = NODES; });
    ASSERT_TRUE(mesh.ready) << topology;
    expectSettledTree(runRounds(mesh, topology, senderCount), topology, senderCount);
}

} // namespace

TEST(PlumtreeSimulationTest, RandomMeshSettlesToTreeWithOneSender) {
    simulate("random mesh", randomMesh(NODES, 7), 1);
}

TEST(PlumtreeSimulationTest, SmallWorldSettlesToTreeWithOneSender) {
    simulate("small world", smallWorld(NODES, 11), 1);
}

TEST(PlumtreeSimulationTest, BridgedClustersSettleToTreeWithOneSender) {
    simulate("two clusters + bridge", twoClustersWithBridge(NODES, 13), 1);
}

// Several senders at once: broadcasts in flight together PRUNE different edges of the same cycle, the shared eager graph
// falls apart and GRAFTs for missing messages put edges back, again and again (SIM 2026-10-06: ~40 GRAFTs per round on
// the random mesh). A link GRAFTed for missing messages 3 times within 10 minutes is pinned eager (docs/router.md 4.3).
TEST(PlumtreeSimulationTest, RandomMeshSettlesWithManySenders) {
    simulate("random mesh", randomMesh(NODES, 7), MANY_SENDERS);
}

TEST(PlumtreeSimulationTest, SmallWorldSettlesWithManySenders) {
    simulate("small world", smallWorld(NODES, 11), MANY_SENDERS);
}

TEST(PlumtreeSimulationTest, BridgedClustersSettleWithManySenders) {
    simulate("two clusters + bridge", twoClustersWithBridge(NODES, 13), MANY_SENDERS);
}
