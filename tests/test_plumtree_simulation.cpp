// Plumtree with a tree root in meshes of different sizes and shapes, several senders at once. Only the root's wave
// shapes the shared tree, so it must settle to a spanning tree (every broadcast costs N - 1 full copies, no GRAFT, no
// PRUNE) and stay settled; when the root goes away or two parts join, the next smallest node id takes over.
// Loopback has no link latency, so the latency-driven tree optimization is barely exercised. Beacons every 300 ms
// instead of 10 s, so a run takes seconds. Network and Router log to stderr; run `./run_test 2>/dev/null` for quiet
// output. The whole matrix (up to 60 nodes, five topologies) is DISABLED_: run it with
// --gtest_also_run_disabled_tests --gtest_filter='*PlumtreeSimulation*'.
#include <gtest/gtest.h>
#include "router_test_mesh.h"

#include <algorithm>
#include <cstdint>
#include <iostream>
#include <random>
#include <set>

using namespace invilite::Mesh;
using namespace invilite::Mesh::TestHelpers;
using namespace std::chrono_literals;

namespace {

constexpr size_t SENDERS        = 5;
constexpr size_t ROUNDS         = 8;
constexpr size_t SETTLED_ROUNDS = 3;
constexpr auto   BEACON_INTERVAL = 300ms;

void addEdge(std::set<std::pair<size_t, size_t>>& edges, size_t a, size_t b) {
    if (a != b) edges.insert({ std::min(a, b), std::max(a, b) });
}

std::vector<Edge> toEdges(const std::set<std::pair<size_t, size_t>>& edges) { return { edges.begin(), edges.end() }; }

std::vector<Edge> randomMesh(size_t count, uint32_t seed) {
    std::mt19937 random(seed);
    std::set<std::pair<size_t, size_t>> edges;
    for (size_t i = 0; i < count; ++i) addEdge(edges, i, (i + 1) % count);
    std::uniform_int_distribution<size_t> pick(0, count - 1);
    while (edges.size() < 2 * count) addEdge(edges, pick(random), pick(random));
    return toEdges(edges);
}

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

// Two random halves; `bridged` joins them by a single link (0 to half)
std::vector<Edge> twoClusters(size_t count, uint32_t seed, bool bridged) {
    std::mt19937 random(seed);
    std::set<std::pair<size_t, size_t>> edges;
    const size_t half = count / 2;
    for (const auto& [first, size] : { std::pair{ size_t{ 0 }, half }, std::pair{ half, count - half } }) {
        std::uniform_int_distribution<size_t> pick(first, first + size - 1);
        for (size_t i = 0; i < size; ++i) addEdge(edges, first + i, first + (i + 1) % size);
        const size_t target = edges.size() + size;
        while (edges.size() < target) addEdge(edges, pick(random), pick(random));
    }
    if (bridged) addEdge(edges, 0, half);
    return toEdges(edges);
}

std::vector<Edge> twoClustersBridged(size_t count, uint32_t seed) { return twoClusters(count, seed, true); }

std::vector<Edge> ringWithLongChords(size_t count, uint32_t) {
    std::set<std::pair<size_t, size_t>> edges;
    for (size_t i = 0; i < count; ++i) {
        addEdge(edges, i, (i + 1) % count);
        if (i % 2 == 0) addEdge(edges, i, (i + count / 4) % count);
    }
    return toEdges(edges);
}

// A grid: the most short cycles per node, the hardest case for cutting cycles consistently
std::vector<Edge> grid(size_t count, uint32_t) {
    size_t width = 1;
    while ((width + 1) * (width + 1) <= count) ++width;
    std::set<std::pair<size_t, size_t>> edges;
    for (size_t i = 0; i < count; ++i) {
        if ((i + 1) % width != 0 && i + 1 < count) addEdge(edges, i, i + 1);
        if (i + width < count) addEdge(edges, i, i + width);
    }
    return toEdges(edges);
}

struct Topology {
    const char*     name;
    std::vector<Edge> (*make)(size_t, uint32_t);
};

const Topology RANDOM_MESH{ "random mesh", randomMesh };
const Topology SMALL_WORLD{ "small world", smallWorld };
const Topology TWO_CLUSTERS{ "two clusters + bridge", twoClustersBridged };
const Topology LONG_CHORDS{ "ring + long chords", ringWithLongChords };
const Topology GRID{ "grid", grid };

struct Totals {
    uint64_t fullCopies = 0;
    uint64_t grafts = 0;
    uint64_t graftsForMissing = 0;
    uint64_t prunes = 0;
    uint64_t beacons = 0;
};

Totals totals(const RouterMesh& mesh, const std::set<size_t>& live) {
    Totals sum;
    for (size_t i : live) {
        const RouterStatistics stats = mesh.routers[i]->getStatistics();
        sum.fullCopies       += stats.fullMessagesSent;
        sum.grafts           += stats.graftsSent;
        sum.graftsForMissing += stats.graftsForMissing;
        sum.prunes           += stats.prunesSent;
        sum.beacons          += stats.treeBeaconsSent;
    }
    return sum;
}

struct RoundCost {
    uint64_t fullCopies = 0;
    uint64_t expectedForTree = 0;
    uint64_t grafts = 0;
    uint64_t graftsForMissing = 0;
    uint64_t prunes = 0;
};

void withTreeRoot(size_t, RouterConfig& config) {
    config.treeRoot.enabled        = true;
    config.treeRoot.beaconInterval = BEACON_INTERVAL;
}

// Every connection comes from 127.0.0.1: the per-address inbound limit (5) would refuse well-connected nodes. Outbound
// hard has room for an edge added later (merge).
void adjustNetwork(NetworkConfig& config) {
    config.connectionLimits.inbound.perAddress = 255;
    config.connectionLimits.inbound.soft       = 64;
    config.connectionLimits.outbound.hard      = 32;
}

std::set<size_t> nodesUpTo(size_t count) {
    std::set<size_t> nodes;
    for (size_t i = 0; i < count; ++i) nodes.insert(i);
    return nodes;
}

size_t smallestIdNode(const RouterMesh& mesh, const std::set<size_t>& among) {
    size_t smallest = *among.begin();
    for (size_t i : among) if (mesh.id(i) < mesh.id(smallest)) smallest = i;
    return smallest;
}

std::optional<std::chrono::milliseconds> awaitRootAgreement(const RouterMesh& mesh, const std::set<size_t>& among) {
    const PeerId root = mesh.id(smallestIdNode(mesh, among));
    const auto start = std::chrono::steady_clock::now();
    const bool agreed = waitUntil([&] {
        for (size_t i : among) if (mesh.routers[i]->getTreeRoot() != root) return false;
        return true;
    }, 15s);
    if (!agreed) return std::nullopt;
    return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start);
}

// Rounds of simultaneous broadcasts from SENDERS live nodes; every message must reach every other live node once.
std::vector<RoundCost> runRounds(RouterMesh& mesh, const std::string& label, const std::set<size_t>& live, size_t roundCount) {
    const std::vector<size_t> liveNodes(live.begin(), live.end());
    std::vector<size_t> senders;
    for (size_t i = 0; i < SENDERS; ++i) senders.push_back(liveNodes[i * liveNodes.size() / SENDERS]);

    std::vector<RoundCost> rounds;
    for (size_t round = 0; round < roundCount; ++round) {
        const Totals before = totals(mesh, live);
        std::vector<std::pair<size_t, uint64_t>> sent;
        for (size_t sender : senders) sent.emplace_back(sender, mesh.routers[sender]->broadcast(0x10, 0, { static_cast<uint8_t>(round) }).value());
        for (const auto& [sender, msgId] : sent) {
            EXPECT_TRUE(waitUntil([&] {
                for (size_t node : live) if (node != sender && mesh.recorders[node]->countOf(mesh.id(sender), msgId) == 0) return false;
                return true;
            }, 10s)) << label << ": round " << round << ", sender " << sender;
        }
        std::this_thread::sleep_for(700ms);
        for (const auto& [sender, msgId] : sent) {
            for (size_t node : live) {
                if (node == sender) continue;
                EXPECT_EQ(mesh.recorders[node]->countOf(mesh.id(sender), msgId), 1u) << label << ": round " << round << ", node " << node;
            }
        }
        const Totals after = totals(mesh, live);
        rounds.push_back({ after.fullCopies - before.fullCopies, (senders.size() + after.beacons - before.beacons) * (live.size() - 1),
                           after.grafts - before.grafts, after.graftsForMissing - before.graftsForMissing, after.prunes - before.prunes });
    }
    return rounds;
}

size_t claimers(const RouterMesh& mesh, const std::set<size_t>& live) {
    size_t count = 0;
    for (size_t i : live) if (mesh.routers[i]->getStatistics().treeBeaconsSent > 0) ++count;
    return count;
}

void report(const std::string& label, const std::vector<RoundCost>& rounds, std::chrono::milliseconds agreedAfter, size_t claimed) {
    std::cout << "[ plumtree ] " << label << ": root agreed after " << agreedAfter.count() << " ms, " << claimed
              << " node(s) ever claimed it; per round full copies (a tree) / GRAFT (for missing) / PRUNE:";
    for (const RoundCost& cost : rounds) std::cout << "  " << cost.fullCopies << " (" << cost.expectedForTree << ")/" << cost.grafts << " (" << cost.graftsForMissing << ")/" << cost.prunes;
    std::cout << std::endl;
}

// Copies are compared over the settled rounds together, within one beacon's copies, because a beacon can be halfway
// through the network when a measurement starts or ends. No GRAFT and no PRUNE is the strict part.
void expectSettledTree(const std::vector<RoundCost>& rounds, const std::string& label, size_t liveNodes) {
    uint64_t copies = 0, expected = 0;
    for (size_t round = rounds.size() - SETTLED_ROUNDS; round < rounds.size(); ++round) {
        copies   += rounds[round].fullCopies;
        expected += rounds[round].expectedForTree;
        EXPECT_EQ(rounds[round].grafts, 0u) << label << ": round " << round;
        EXPECT_EQ(rounds[round].prunes, 0u) << label << ": round " << round;
    }
    const uint64_t oneBeacon = liveNodes - 1;
    EXPECT_LE(copies, expected + oneBeacon) << label << ": the last " << SETTLED_ROUNDS << " rounds are not a spanning tree";
    EXPECT_GE(copies + oneBeacon, expected) << label;
}

// Connected parts of the declared graph among `live` nodes; removing the root can split it.
std::vector<std::set<size_t>> connectedParts(const std::vector<Edge>& edges, const std::set<size_t>& live) {
    std::vector<std::set<size_t>> parts;
    std::set<size_t> placed;
    for (size_t start : live) {
        if (placed.contains(start)) continue;
        std::set<size_t> part{ start };
        std::vector<size_t> frontier{ start };
        while (!frontier.empty()) {
            const size_t node = frontier.back();
            frontier.pop_back();
            for (const auto& [a, b] : edges) {
                const size_t other = a == node ? b : b == node ? a : SIZE_MAX;
                if (other != SIZE_MAX && live.contains(other) && part.insert(other).second) frontier.push_back(other);
            }
        }
        placed.insert(part.begin(), part.end());
        parts.push_back(std::move(part));
    }
    return parts;
}

std::string labelOf(const Topology& topology, size_t nodes) { return std::string(topology.name) + ", " + std::to_string(nodes) + " nodes"; }

void simulateSettling(const Topology& topology, size_t nodeCount, uint32_t seed) {
    const std::string label = labelOf(topology, nodeCount);
    RouterMesh mesh(nodeCount, topology.make(nodeCount, seed), withTreeRoot, adjustNetwork);
    ASSERT_TRUE(mesh.ready) << label;
    const std::set<size_t> live = nodesUpTo(nodeCount);
    const auto agreedAfter = awaitRootAgreement(mesh, live);
    ASSERT_TRUE(agreedAfter.has_value()) << label << ": nodes did not agree on the smallest id as root";
    const std::vector<RoundCost> rounds = runRounds(mesh, label, live, ROUNDS);
    report(label, rounds, *agreedAfter, claimers(mesh, live));
    expectSettledTree(rounds, label, live.size());
}

// The root leaves: the next smallest id takes over, the tree settles again. When the root held two parts together, each
// part agrees on its own smallest id; the rounds run in the largest part.
void simulateRootLoss(const Topology& topology, size_t nodeCount, uint32_t seed) {
    const std::string label = labelOf(topology, nodeCount) + ", root stopped";
    const std::vector<Edge> edges = topology.make(nodeCount, seed);
    RouterMesh mesh(nodeCount, edges, withTreeRoot, adjustNetwork);
    ASSERT_TRUE(mesh.ready) << label;
    std::set<size_t> live = nodesUpTo(nodeCount);
    ASSERT_TRUE(awaitRootAgreement(mesh, live).has_value()) << label;
    runRounds(mesh, label, live, 3);

    const size_t root = smallestIdNode(mesh, live);
    mesh.routers[root]->stop();
    mesh.nodes[root]->network->stop();
    live.erase(root);

    const std::vector<std::set<size_t>> parts = connectedParts(edges, live);
    std::optional<std::chrono::milliseconds> agreedAfter;
    for (const std::set<size_t>& part : parts) {
        agreedAfter = awaitRootAgreement(mesh, part);
        ASSERT_TRUE(agreedAfter.has_value()) << label << ": no agreement on the next smallest id (part of " << part.size() << ")";
    }
    const std::set<size_t> largest = *std::max_element(parts.begin(), parts.end(), [](const auto& a, const auto& b) { return a.size() < b.size(); });
    const std::vector<RoundCost> rounds = runRounds(mesh, label, largest, ROUNDS);
    report(label + (parts.size() > 1 ? ", split into " + std::to_string(parts.size()) + " parts" : std::string()), rounds, *agreedAfter, claimers(mesh, largest));
    expectSettledTree(rounds, label, largest.size());
}

// Two parts with a root each join by one link: the smaller root wins everywhere.
void simulateMerge(size_t nodeCount, uint32_t seed) {
    const std::string label = "two parts joined later, " + std::to_string(nodeCount) + " nodes";
    RouterMesh mesh(nodeCount, twoClusters(nodeCount, seed, false), withTreeRoot, adjustNetwork);
    ASSERT_TRUE(mesh.ready) << label;
    const size_t half = nodeCount / 2;
    std::set<size_t> first, second;
    for (size_t i = 0; i < nodeCount; ++i) (i < half ? first : second).insert(i);
    ASSERT_TRUE(awaitRootAgreement(mesh, first).has_value()) << label << ": first part";
    ASSERT_TRUE(awaitRootAgreement(mesh, second).has_value()) << label << ": second part";

    mesh.nodes[0]->network->connectToPeer("127.0.0.1", mesh.nodes[half]->port);
    ASSERT_TRUE(waitUntil([&] { return std::ranges::count(mesh.routers[0]->getNeighbors(), mesh.id(half)) == 1; }, 5s)) << label << ": parts not joined";
    const std::set<size_t> live = nodesUpTo(nodeCount);
    const auto agreedAfter = awaitRootAgreement(mesh, live);
    ASSERT_TRUE(agreedAfter.has_value()) << label << ": no agreement after joining";
    const std::vector<RoundCost> rounds = runRounds(mesh, label, live, ROUNDS);
    report(label, rounds, *agreedAfter, claimers(mesh, live));
    expectSettledTree(rounds, label, live.size());
}

} // namespace

TEST(PlumtreeSimulationTest, RandomMeshSettlesToTreeWithManySenders)     { simulateSettling(RANDOM_MESH, 30, 7); }
TEST(PlumtreeSimulationTest, SmallWorldSettlesToTreeWithManySenders)     { simulateSettling(SMALL_WORLD, 30, 11); }
TEST(PlumtreeSimulationTest, BridgedClustersSettleToTreeWithManySenders) { simulateSettling(TWO_CLUSTERS, 30, 13); }
TEST(PlumtreeSimulationTest, NextSmallestNodeTakesOverWhenRootStops)     { simulateRootLoss(RANDOM_MESH, 30, 7); }
TEST(PlumtreeSimulationTest, JoinedPartsAgreeOnSmallerRoot)              { simulateMerge(30, 17); }

class PlumtreeSimulationMatrix : public testing::TestWithParam<std::tuple<size_t, Topology>> {};

TEST_P(PlumtreeSimulationMatrix, SettlesToTreeWithManySenders) {
    const auto& [nodes, topology] = GetParam();
    simulateSettling(topology, nodes, static_cast<uint32_t>(nodes * 31));
}

TEST_P(PlumtreeSimulationMatrix, NextSmallestNodeTakesOverWhenRootStops) {
    const auto& [nodes, topology] = GetParam();
    simulateRootLoss(topology, nodes, static_cast<uint32_t>(nodes * 37));
}

INSTANTIATE_TEST_SUITE_P(DISABLED_Sizes, PlumtreeSimulationMatrix,
                         testing::Combine(testing::Values(size_t{ 10 }, size_t{ 30 }, size_t{ 60 }),
                                          testing::Values(RANDOM_MESH, SMALL_WORLD, TWO_CLUSTERS, LONG_CHORDS, GRID)),
                         [](const testing::TestParamInfo<PlumtreeSimulationMatrix::ParamType>& info) {
                             std::string name = std::to_string(std::get<0>(info.param)) + "_" + std::get<1>(info.param).name;
                             for (char& c : name) if (!std::isalnum(static_cast<unsigned char>(c))) c = '_';
                             return name;
                         });

TEST(PlumtreeSimulationTest, DISABLED_MergeAtSixtyNodes) { simulateMerge(60, 19); }
