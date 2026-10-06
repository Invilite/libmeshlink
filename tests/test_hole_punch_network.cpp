// F7-c: NAT hole punching through Network — two nodes nobody can dial meet through their common neighbor R.
// On loopback a SYN that arrives before the other side opened would get RST, so the test drops early SYNs the way a NAT
// does (SynBlackhole on the ports A and B use towards R). Network logs to stderr; run `./run_test 2>/dev/null`.
#include <gtest/gtest.h>
#include "meshlink/network.h"
#include "collecting_log_sink.h"
#include "network_test_node.h"

#include <algorithm>
#include <atomic>
#include <fstream>
#include <memory>
#include <sstream>
#include <string>
#include <vector>

using namespace invilite::Mesh;
using namespace invilite::Mesh::TestHelpers;
using namespace std::chrono_literals;

namespace {

// Local ports of established IPv4 connections to `remotePort` (from /proc/net/tcp — the dialers' side of them)
std::vector<uint16_t> localPortsConnectedTo(uint16_t remotePort) {
    std::ifstream table("/proc/net/tcp");
    std::string   line;
    std::getline(table, line);                                                      // header
    std::vector<uint16_t> ports;
    while (std::getline(table, line)) {
        std::istringstream fields(line);
        std::string slot, local, remote, state;
        fields >> slot >> local >> remote >> state;
        if (state != "01") continue;                                                // ESTABLISHED
        const auto portOf = [](const std::string& endpoint) { return static_cast<uint16_t>(std::stoul(endpoint.substr(endpoint.find(':') + 1), nullptr, 16)); };
        if (portOf(remote) == remotePort) ports.push_back(portOf(local));
    }
    return ports;
}

bool isConnectedTo(const TestNode& node, const TestNode& other) {
    const auto peers = node.network->getConnectedPeers();
    return std::find(peers.begin(), peers.end(), other.identity->getPeerId()) != peers.end();
}

struct MessageCounter : NetworkEventListener {
    void onMessageReceived(const NetworkMessage&) override { ++received; }
    std::atomic<int> received{0};
};

// Nodes "behind NAT": they announce nothing, so nobody dials them and they never dial each other
void announceNothing(NetworkConfig& config) { config.announcedAddresses.clear(); }

} // namespace

TEST(HolePunchNetworkTest, TwoNodesNobodyCanDialConnectDirectlyThroughCommonNeighbor) {
    const auto secret = makeSecret();
    TestNode coordinator(secret, "R");
    TestNode first(secret, "first", announceNothing), second(secret, "second", announceNothing);
    TestNode& smaller = first.identity->getPeerId() < second.identity->getPeerId() ? first : second;   // only the smaller asks
    TestNode& larger  = &smaller == &first ? second : first;
    const auto messagesAtLarger = std::make_shared<MessageCounter>();
    larger.network->addListener(messagesAtLarger);

    coordinator.network->start();
    smaller.network->start();
    larger.network->start();
    smaller.network->connectToPeer("127.0.0.1", coordinator.port);
    larger.network->connectToPeer("127.0.0.1", coordinator.port);
    ASSERT_TRUE(waitUntil([&] { return coordinator.network->getConnectedPeerCount() == 2; }, 5s));

    std::vector<std::unique_ptr<SynBlackhole>> nats;
    const auto ports = localPortsConnectedTo(coordinator.port);
    ASSERT_EQ(ports.size(), 2u);
    for (const uint16_t port : ports) nats.push_back(std::make_unique<SynBlackhole>(port));

    smaller.network->requestHolePunch(larger.identity->getPeerId());
    ASSERT_TRUE(waitUntil([&] { return isConnectedTo(smaller, larger) && isConnectedTo(larger, smaller); }, 8s));

    // The punched link carries traffic, and both links to R stay up next to it (different four-tuples)
    EXPECT_GT(smaller.network->sendToPeer(larger.identity->getPeerId(), { 0x01, 0x00, 0x01, 'h', 'i' }), 0);
    EXPECT_TRUE(waitUntil([&] { return messagesAtLarger->received == 1; }, 3s));
    EXPECT_EQ(coordinator.network->getConnectedPeerCount(), 2u);
    EXPECT_TRUE(isConnectedTo(smaller, coordinator));
    EXPECT_TRUE(isConnectedTo(larger, coordinator));

    larger.network->stop();
    smaller.network->stop();
    coordinator.network->stop();
}

TEST(HolePunchNetworkTest, WithoutCommonNeighborThePairRests) {
    const auto secret = makeSecret();
    auto sink = std::make_shared<CollectingLogSink>();
    TestNode coordinator(secret, "R");
    TestNode first(secret, "first", announceNothing, std::make_shared<Logger>(sink, LogLevel::Info));
    TestNode second(secret, "second", announceNothing, std::make_shared<Logger>(sink, LogLevel::Info));
    TestNode& asking = first.identity->getPeerId() < second.identity->getPeerId() ? first : second;
    TestNode& target = &asking == &first ? second : first;                          // never started: only its PeerId is used

    coordinator.network->start();
    asking.network->start();
    asking.network->connectToPeer("127.0.0.1", coordinator.port);                  // the target is nobody's neighbor
    ASSERT_TRUE(waitUntil([&] { return coordinator.network->getConnectedPeerCount() == 1; }, 5s));

    asking.network->requestHolePunch(target.identity->getPeerId());
    ASSERT_TRUE(waitUntil([&] { return sink->countContaining(LogLevel::Info, "no neighbor coordinates a hole punch") == 1; }, 3s));
    EXPECT_EQ(sink->countContaining(LogLevel::Info, "not a neighbor"), 1u);

    asking.network->requestHolePunch(target.identity->getPeerId());                // resting: not asked again
    std::this_thread::sleep_for(300ms);
    EXPECT_EQ(sink->countContaining(LogLevel::Info, "no neighbor coordinates a hole punch"), 1u);
    EXPECT_TRUE(isConnectedTo(asking, coordinator));

    asking.network->stop();
    coordinator.network->stop();
}
