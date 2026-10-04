// Router integration tests: real Network instances in one process over loopback TCP, a Router on top.
// Network and Router log to stderr; run `./run_test 2>/dev/null` for quiet output.
#include <gtest/gtest.h>
#include "meshlink/router.h"
#include "meshlink/router_wire.h"
#include "network_test_node.h"

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

} // namespace

TEST(RouterTest, TracksNeighborsFromNetworkEvents) {
    const auto secret = makeSecret();
    TestNode alpha(secret, "alpha");
    TestNode beta(secret, "beta");
    TestNode gamma(secret, "gamma");
    alpha.network->start();
    beta.network->start();
    gamma.network->start();
    Router router(*alpha.network);
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

    Router router(*alpha.network);
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
    Router router(*alpha.network);
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
