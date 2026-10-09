#include <gtest/gtest.h>
#include "network_test_node.h"
#include "collecting_log_sink.h"

using namespace invilite::Mesh;
using namespace invilite::Mesh::TestHelpers;
using namespace std::chrono_literals;

// The failed dial was lost among info messages on the first real network, so it must stand out as a warning
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

// Probes target peers of unknown or lost reachability, so failing is their normal outcome: Info, never a Warning stream
TEST(NetworkLoggingTest, ProbeFailureIsNotAWarning) {
    auto sink   = std::make_shared<CollectingLogSink>();
    auto secret = makeSecret();
    TestNode node(secret, "prober", {}, std::make_shared<Logger>(sink, LogLevel::Info));
    const auto ghost  = LocalIdentity::generate();
    const auto record = makeSignedRecord(ghost, { ipv4("127.0.0.1", pickUnusedPort()) }, std::chrono::system_clock::now());
    node.directory->upsertPeer(record.peerId, [&](KnownPeer& entry, bool) { entry.record = record; });
    node.network->start();

    EXPECT_TRUE(waitUntil([&] { return sink->countContaining(LogLevel::Info, "probe to") > 0; }, 3s));
    node.network->stop();
    EXPECT_EQ(sink->countAtLevel(LogLevel::Warning), 0u);
}

// A neighbor can mint identities for free: a full address book dropping 30 gossiped records logs once, not 30 times
TEST(NetworkLoggingTest, FullAddressBookLogsOncePerWindow) {
    auto sink   = std::make_shared<CollectingLogSink>();
    auto secret = makeSecret();
    TestNode bounded(secret, "bounded", [](NetworkConfig& config) { config.maxKnownPeers = 1; }, std::make_shared<Logger>(sink, LogLevel::Info));
    TestNode gossiper(secret, "gossiper", [](NetworkConfig& config) { config.initialPexBatchSize = 30; });
    for (int i = 0; i < 30; ++i) {
        const auto someone = LocalIdentity::generate();
        const auto record  = makeSignedRecord(someone, { ipv4("127.0.0.1", static_cast<uint16_t>(20000 + i)) }, std::chrono::system_clock::now());
        gossiper.directory->upsertPeer(record.peerId, [&](KnownPeer& entry, bool) { entry.record = record; entry.hasEverConnected = true; });
    }
    bounded.network->start();
    gossiper.network->start();
    bounded.network->connectToPeer("127.0.0.1", gossiper.port);

    ASSERT_TRUE(waitUntil([&] { return sink->countContaining(LogLevel::Warning, "address book full") > 0; }, 5s));
    std::this_thread::sleep_for(500ms);                                              // the whole PEX batch is processed
    EXPECT_EQ(sink->countContaining(LogLevel::Warning, "address book full"), 1u);
    bounded.network->stop();
    gossiper.network->stop();
}
