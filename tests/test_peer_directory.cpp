#include <gtest/gtest.h>
#include "meshlink/peer_directory.h"

#include <thread>

using namespace invilite::Mesh;

namespace {

PeerId peerIdOf(uint8_t tag) {
    PeerId id{};
    id[0] = tag;
    id[31] = tag;
    return id;
}

} // namespace

TEST(PeerDirectoryTest, UpsertCreatesEntryAndReportsItAsNew) {
    PeerDirectory directory;
    bool reportedNew = false;

    directory.upsertPeer(peerIdOf(1), [&](KnownPeer& entry, bool isNew) { reportedNew = isNew; entry.announceCount = 7; });

    EXPECT_TRUE(reportedNew);
    ASSERT_TRUE(directory.findPeer(peerIdOf(1)).has_value());
    EXPECT_EQ(directory.findPeer(peerIdOf(1))->announceCount, 7);
    EXPECT_EQ(directory.size(), 1u);
}

TEST(PeerDirectoryTest, UpsertOnExistingEntryReportsItAsNotNew) {
    PeerDirectory directory;
    directory.upsertPeer(peerIdOf(1), [](KnownPeer&, bool) {});

    bool reportedNew = true;
    directory.upsertPeer(peerIdOf(1), [&](KnownPeer&, bool isNew) { reportedNew = isNew; });

    EXPECT_FALSE(reportedNew);
    EXPECT_EQ(directory.size(), 1u);
}

TEST(PeerDirectoryTest, MutateDoesNotCreateMissingEntry) {
    PeerDirectory directory;

    const bool invoked = directory.mutatePeer(peerIdOf(1), [](KnownPeer&) {});

    EXPECT_FALSE(invoked);
    EXPECT_EQ(directory.size(), 0u);
}

TEST(PeerDirectoryTest, FindReturnsCopyNotReference) {
    PeerDirectory directory;
    directory.upsertPeer(peerIdOf(1), [](KnownPeer& entry, bool) { entry.announceCount = 1; });

    auto copy = directory.findPeer(peerIdOf(1));
    copy->announceCount = 99;

    EXPECT_EQ(directory.findPeer(peerIdOf(1))->announceCount, 1);
}

TEST(PeerDirectoryTest, RemoveDeletesEntry) {
    PeerDirectory directory;
    directory.upsertPeer(peerIdOf(1), [](KnownPeer&, bool) {});

    directory.removePeer(peerIdOf(1));

    EXPECT_FALSE(directory.findPeer(peerIdOf(1)).has_value());
}

// Meant for ThreadSanitizer builds (data races); a normal build only checks for lost updates.
TEST(PeerDirectoryTest, ConcurrentMutationsAreNotLost) {
    PeerDirectory directory;
    directory.upsertPeer(peerIdOf(1), [](KnownPeer&, bool) {});
    constexpr int threadCount = 8;
    constexpr int incrementsPerThread = 1000;

    std::vector<std::thread> threads;
    for (int t = 0; t < threadCount; ++t) {
        threads.emplace_back([&] {
            for (int i = 0; i < incrementsPerThread; ++i) {
                directory.mutatePeer(peerIdOf(1), [](KnownPeer& entry) { ++entry.consecutiveProbeFailures; });   // uint8_t wraps, so the total is checked modulo 256
                (void)directory.listPeers();
            }
        });
    }
    for (auto& thread : threads) thread.join();

    EXPECT_EQ(directory.findPeer(peerIdOf(1))->consecutiveProbeFailures, static_cast<uint8_t>(threadCount * incrementsPerThread));
}
