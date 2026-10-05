#include <gtest/gtest.h>
#include "meshlink/broadcast_cache.h"

using namespace invilite::Mesh;
using namespace std::chrono_literals;

namespace {

const auto T0 = std::chrono::steady_clock::time_point(std::chrono::seconds(1000));

PeerId peerId(uint8_t fill) { PeerId id; id.fill(fill); return id; }

// Signature bytes need not be valid — the cache never verifies
RoutedMessage broadcast(uint8_t sender, uint64_t msgId, size_t payloadSize, uint8_t ttlRemaining = 10) {
    RoutedMessage m;
    m.group        = 0x10;
    m.mode         = RoutingMode::Broadcast;
    m.ttlInitial   = 16;
    m.ttlRemaining = ttlRemaining;
    m.msgId        = msgId;
    m.sender       = peerId(sender);
    m.signature.assign(64, 0x5A);
    m.payload.assign(payloadSize, 0x01);
    return m;
}

RoutedMessageKey keyOf(const RoutedMessage& m) { return { m.sender, m.msgId }; }

constexpr size_t OVERHEAD = 3 + 48 + 64;                                                       // encodedSize without payload

} // namespace

TEST(BroadcastCacheTest, StoresFirstCopyAndFindsItByKey) {
    BroadcastCache cache(30s, 1 << 20);
    const RoutedMessage m = broadcast(1, 7, 10);
    EXPECT_TRUE(cache.store(m, T0));
    EXPECT_FALSE(cache.store(broadcast(1, 7, 10, 3), T0));                                     // first copy wins
    ASSERT_NE(cache.find(keyOf(m)), nullptr);
    EXPECT_EQ(*cache.find(keyOf(m)), m);
    EXPECT_EQ(cache.find({ peerId(2), 7 }), nullptr);                                          // same msgId, other sender: another message
    EXPECT_EQ(cache.bytes(), OVERHEAD + 10);
}

TEST(BroadcastCacheTest, ForgetsMessagesAfterRetention) {
    BroadcastCache cache(30s, 1 << 20);
    const RoutedMessage old = broadcast(1, 1, 5);
    cache.store(old, T0);
    cache.store(broadcast(1, 2, 5), T0 + 20s);
    cache.dropExpired(T0 + 29s);
    EXPECT_EQ(cache.size(), 2u);
    cache.dropExpired(T0 + 30s);
    EXPECT_EQ(cache.find(keyOf(old)), nullptr);
    EXPECT_EQ(cache.size(), 1u);
    EXPECT_EQ(cache.bytes(), OVERHEAD + 5);
}

TEST(BroadcastCacheTest, ByteLimitEvictsOldestFirstAndRefusesOversize) {
    BroadcastCache cache(30s, 3 * (OVERHEAD + 100));
    for (uint64_t id = 1; id <= 3; ++id) ASSERT_TRUE(cache.store(broadcast(1, id, 100), T0 + std::chrono::seconds(id)));
    EXPECT_EQ(cache.bytes(), 3 * (OVERHEAD + 100));

    ASSERT_TRUE(cache.store(broadcast(1, 4, 100), T0 + 4s));
    EXPECT_EQ(cache.find({ peerId(1), 1 }), nullptr);                                          // oldest went
    EXPECT_NE(cache.find({ peerId(1), 2 }), nullptr);
    EXPECT_EQ(cache.bytes(), 3 * (OVERHEAD + 100));

    ASSERT_TRUE(cache.store(broadcast(1, 5, 2 * 100 + OVERHEAD), T0 + 5s));                    // needs two slots
    EXPECT_EQ(cache.size(), 2u);
    EXPECT_NE(cache.find({ peerId(1), 4 }), nullptr);

    EXPECT_FALSE(cache.store(broadcast(1, 6, 3 * (OVERHEAD + 100)), T0 + 6s));                 // larger than the whole limit
    EXPECT_EQ(cache.size(), 2u);                                                               // and evicted nothing for it
}

TEST(BroadcastCacheTest, EachNeighborGetsTheFullCopyOnce) {
    BroadcastCache cache(30s, 1 << 20);
    const RoutedMessage m = broadcast(1, 7, 10);
    cache.store(m, T0);
    EXPECT_TRUE(cache.markSentTo(keyOf(m), peerId(0xA)));
    EXPECT_FALSE(cache.markSentTo(keyOf(m), peerId(0xA)));                                     // a repeated GRAFT gets nothing more
    EXPECT_TRUE(cache.markSentTo(keyOf(m), peerId(0xB)));
    EXPECT_FALSE(cache.markSentTo({ peerId(1), 8 }, peerId(0xA)));                             // not held
}

// The copy queued to a neighbor whose connection broke may never have arrived
TEST(BroadcastCacheTest, NeighborThatLeftCanBeSentEverythingAgain) {
    BroadcastCache cache(30s, 1 << 20);
    const RoutedMessage first = broadcast(1, 1, 10), second = broadcast(1, 2, 10);
    cache.store(first, T0);
    cache.store(second, T0);
    cache.markSentTo(keyOf(first), peerId(0xA));
    cache.markSentTo(keyOf(second), peerId(0xA));
    cache.markSentTo(keyOf(second), peerId(0xB));

    cache.forgetNeighbor(peerId(0xA));
    EXPECT_TRUE(cache.markSentTo(keyOf(first), peerId(0xA)));
    EXPECT_TRUE(cache.markSentTo(keyOf(second), peerId(0xA)));
    EXPECT_FALSE(cache.markSentTo(keyOf(second), peerId(0xB)));                                // others untouched
}

TEST(BroadcastCacheTest, ReplaceTakesBetterCopyAndClearsWhoGotIt) {
    BroadcastCache cache(30s, 1 << 20);
    const RoutedMessage low = broadcast(1, 7, 10, 1);
    cache.store(low, T0);
    cache.markSentTo(keyOf(low), peerId(0xA));

    RoutedMessage better = broadcast(1, 7, 10, 9);
    better.extensions = { { 0x40, { 1, 2 } } };                                                // per-hop extension changes the size
    ASSERT_TRUE(cache.replace(better, T0 + 1s));
    EXPECT_EQ(cache.find(keyOf(low))->ttlRemaining, 9);
    EXPECT_EQ(cache.size(), 1u);
    EXPECT_EQ(cache.bytes(), RouterWire::encodedSize(better));
    EXPECT_TRUE(cache.markSentTo(keyOf(low), peerId(0xA)));                                    // the better copy goes to everyone again

    EXPECT_FALSE(cache.replace(broadcast(1, 8, 10), T0 + 1s));                                 // nothing to replace
    EXPECT_EQ(cache.size(), 1u);
}
