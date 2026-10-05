// P7: Network logs through the injected Logger with syslog levels (docs/logging.md 3.3).
#include <gtest/gtest.h>
#include "network_test_node.h"
#include "collecting_log_sink.h"

using namespace invilite::Mesh;
using namespace invilite::Mesh::TestHelpers;
using namespace std::chrono_literals;

// The failed dial was lost among info messages on the first real network — it must stand out as a warning
TEST(NetworkLoggingTest, FailedDialIsLoggedAsWarning) {
    auto sink   = std::make_shared<CollectingLogSink>();
    auto secret = makeSecret();
    TestNode node(secret, "dialer", {}, std::make_shared<Logger>(sink, LogLevel::Info));
    node.network->start();

    node.network->connectToPeer("127.0.0.1", pickUnusedPort());                     // nothing listens there
    EXPECT_TRUE(waitUntil([&] { return sink->countContaining(LogLevel::Warning, "outgoing connect") > 0; }, 7s));
    node.network->stop();
}

TEST(NetworkLoggingTest, DefaultThresholdHidesDebug) {
    auto sink   = std::make_shared<CollectingLogSink>();
    auto secret = makeSecret();
    TestNode alpha(secret, "alpha", {}, std::make_shared<Logger>(sink, LogLevel::Info));
    TestNode beta(secret, "beta", {}, std::make_shared<Logger>(sink, LogLevel::Info));
    alpha.network->start();
    beta.network->start();

    alpha.network->connectToPeer("127.0.0.1", beta.port);
    EXPECT_TRUE(waitUntil([&] { return sink->countContaining(LogLevel::Notice, "connected") >= 2; }, 7s));   // both sides announce the peer
    alpha.network->stop();
    beta.network->stop();
    EXPECT_EQ(sink->countAtLevel(LogLevel::Debug), 0u);
}

TEST(NetworkLoggingTest, NetworkWithoutLoggerStillRuns) {
    auto secret = makeSecret();
    TestNode node(secret, "plain");
    ASSERT_NE(node.network->getLogger(), nullptr);
    node.network->start();
    node.network->stop();
}

TEST(NetworkLoggingTest, ListenFailureNamesTheCause) {
    auto sink   = std::make_shared<CollectingLogSink>();
    auto secret = makeSecret();
    TestNode first(secret, "first");
    first.network->start();
    TestNode second(secret, "second", [&](NetworkConfig& config) { config.listenPort = first.port; }, std::make_shared<Logger>(sink, LogLevel::Info));

    EXPECT_THROW(second.network->start(), std::runtime_error);
    EXPECT_EQ(sink->countContaining(LogLevel::Critical, "bind"), 1u);
    first.network->stop();
}
