#include <gtest/gtest.h>
#include "meshlink/router.h"
#include "meshlink/router_wire.h"
#include "network_test_node.h"
#include "collecting_log_sink.h"

using namespace invilite::Mesh;
using namespace invilite::Mesh::TestHelpers;
using namespace std::chrono_literals;

// A neighbor sending a stream of malformed control frames must not flood the log.
TEST(RouterLoggingTest, MalformedPruneFloodLogsOnce) {
    auto sink   = std::make_shared<CollectingLogSink>();
    auto secret = makeSecret();
    TestNode alpha(secret, "alpha", {}, std::make_shared<Logger>(sink, LogLevel::Info));
    TestNode beta(secret, "beta");
    alpha.network->start();
    beta.network->start();
    beta.network->connectToPeer("127.0.0.1", alpha.port);
    ASSERT_TRUE(waitUntil([&] { return alpha.network->getConnectedPeerCount() == 1 && beta.network->getConnectedPeerCount() == 1; }, 5s));

    Router router(*alpha.network, alpha.directory, alpha.identity);
    router.start();
    ASSERT_TRUE(waitUntil([&] { return router.getNeighbors().size() == 1; }, 5s));

    const std::vector<uint8_t> malformedPrune = { RouterWire::ROUTER_PROTOCOL_GROUP, 0x00, static_cast<uint8_t>(RouterWire::SUBTYPE_PRUNE), 0x01 };
    for (int i = 0; i < 20; ++i) ASSERT_GT(beta.network->sendToPeer(alpha.identity->getPeerId(), malformedPrune), 0);

    EXPECT_TRUE(waitUntil([&] { return sink->countContaining(LogLevel::Warning, "malformed PRUNE") > 0; }, 5s));
    std::this_thread::sleep_for(300ms);
    EXPECT_EQ(sink->countContaining(LogLevel::Warning, "malformed PRUNE"), 1u);

    router.stop();
    alpha.network->stop();
    beta.network->stop();
}
