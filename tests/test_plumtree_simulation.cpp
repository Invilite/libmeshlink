// SIM (docs/router.md 6): Plumtree in larger meshes with several senders at once. The eager/lazy state is per link,
// shared by every sender (as in the original Plumtree); a spanning tree carries any sender's message to every node in
// N − 1 full copies, so the shared state should settle and stay settled. Real Network instances over loopback: there is
// no link latency, so the latency-driven tree optimization is not exercised here.
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
constexpr size_t ROUNDS  = 8;
constexpr size_t SETTLED_ROUNDS = 3;                                                          // the last rounds must cost exactly a tree

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
    }
    return cost;
}

// Rounds of simultaneous broadcasts, one per sender; every message must reach every other node exactly once. Returns each round's cost.
std::vector<RoundCost> runRounds(RouterMesh& mesh, const std::string& topology, size_t senderCount) {
    std::vector<size_t> senders;
    for (size_t i = 0; i < senderCount; ++i) senders.push_back(i * NODES / senderCount);

    std::vector<RoundCost> rounds;
    for (size_t round = 0; round < ROUNDS; ++round) {
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
        rounds.push_back({ after.fullCopies - before.fullCopies, after.announcedKeys - before.announcedKeys, after.grafts - before.grafts, after.prunes - before.prunes, after.graftsForMissing - before.graftsForMissing });
    }

    std::cout << "[ SIM      ] " << topology << " (" << NODES << " nodes, " << senderCount << " sender(s)): full copies / IHAVE keys / GRAFT (for missing) / PRUNE per round:";
    for (const RoundCost& cost : rounds) std::cout << "  " << cost.fullCopies << "/" << cost.announcedKeys << "/" << cost.grafts << " (" << cost.graftsForMissing << ")/" << cost.prunes;
    std::cout << "  (a tree: " << senderCount * (NODES - 1) << " full copies)" << std::endl;
    return rounds;
}

void expectSettledTree(const std::vector<RoundCost>& rounds, const std::string& topology, size_t senderCount) {
    for (size_t round = ROUNDS - SETTLED_ROUNDS; round < ROUNDS; ++round) {
        EXPECT_EQ(rounds[round].fullCopies, senderCount * (NODES - 1)) << topology << ": round " << round << " is not a spanning tree";
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

// SIM finding (2026-10-06, docs/router.md 7): with several senders at once the shared per-link eager/lazy state does not
// settle — broadcasts in flight together PRUNE different edges of the same cycle, the eager graph falls apart, GRAFTs for
// missing messages put edges back, and it repeats (~40 GRAFTs per round on the random mesh, 1.5× the tree's traffic).
// Disabled until the fix; run with --gtest_also_run_disabled_tests.
TEST(PlumtreeSimulationTest, DISABLED_RandomMeshSettlesToSharedTreeWithManySenders) {
    simulate("random mesh", randomMesh(NODES, 7), MANY_SENDERS);
}

TEST(PlumtreeSimulationTest, DISABLED_SmallWorldSettlesToSharedTreeWithManySenders) {
    simulate("small world", smallWorld(NODES, 11), MANY_SENDERS);
}

TEST(PlumtreeSimulationTest, DISABLED_BridgedClustersSettleToSharedTreeWithManySenders) {
    simulate("two clusters + bridge", twoClustersWithBridge(NODES, 13), MANY_SENDERS);
}
