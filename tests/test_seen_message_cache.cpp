#include <gtest/gtest.h>
#include "meshlink/seen_message_cache.h"

#include <set>

using namespace invilite::Mesh;
using namespace std::chrono_literals;

namespace {

RoutedMessageKey key(uint8_t senderFill, uint64_t msgId) {
    RoutedMessageKey k;
    k.sender.fill(senderFill);
    k.msgId = msgId;
    return k;
}

const auto T0 = std::chrono::steady_clock::time_point{} + 1h;

} // namespace

TEST(SeenMessageCacheTest, RemembersKeyPerSenderAndMessageId) {
    SeenMessageCache cache(600s, 100);
    cache.remember(key(1, 42), 1000, T0);
    EXPECT_TRUE(cache.contains(key(1, 42)));
    EXPECT_FALSE(cache.contains(key(2, 42)));
    EXPECT_FALSE(cache.contains(key(1, 43)));
    cache.remember(key(1, 42), 1000, T0 + 1s);
    EXPECT_EQ(cache.size(), 1u);
}

TEST(SeenMessageCacheTest, ForgetsKeysOlderThanWindow) {
    SeenMessageCache cache(600s, 100);
    cache.remember(key(1, 1), 1000, T0);
    cache.remember(key(1, 2), 1300, T0 + 300s);
    cache.remember(key(1, 3), 1600, T0 + 600s);
    EXPECT_TRUE(cache.contains(key(1, 1)));
    cache.remember(key(1, 4), 1601, T0 + 601s);
    EXPECT_FALSE(cache.contains(key(1, 1)));
    EXPECT_TRUE(cache.contains(key(1, 2)));
    EXPECT_EQ(cache.size(), 3u);
    EXPECT_FALSE(cache.predatesEvictedKeys(1000));
}

TEST(SeenMessageCacheTest, CapacityEvictsOldestFirst) {
    SeenMessageCache cache(600s, 3);
    for (uint64_t id = 1; id <= 4; ++id) cache.remember(key(1, id), static_cast<uint32_t>(1000 + id), T0 + std::chrono::seconds(id));
    EXPECT_EQ(cache.size(), 3u);
    EXPECT_FALSE(cache.contains(key(1, 1)));
    EXPECT_TRUE(cache.contains(key(1, 2)));
    EXPECT_TRUE(cache.contains(key(1, 4)));
}

TEST(SeenMessageCacheTest, HashSpreadsIdsOfOneSender) {
    // A sender picks its own msgIds, so ids differing only in high bits must not collide.
    RoutedMessageKeyHash hash;
    std::set<size_t> buckets;
    for (uint64_t i = 0; i < 64; ++i) buckets.insert(hash(key(1, i << 56)) % 1024);
    EXPECT_GT(buckets.size(), 50u);
}

// A flood that pushes keys out early must not make their messages replayable: everything sent up to the newest evicted
// key counts as possibly seen.
TEST(SeenMessageCacheTest, CapacityEvictionRaisesReplayFloor) {
    SeenMessageCache cache(600s, 2);
    EXPECT_FALSE(cache.predatesEvictedKeys(0));
    cache.remember(key(1, 1), 1005, T0);
    cache.remember(key(1, 2), 1003, T0);
    cache.remember(key(1, 3), 1010, T0);
    EXPECT_TRUE(cache.predatesEvictedKeys(1005));
    EXPECT_TRUE(cache.predatesEvictedKeys(900));
    EXPECT_FALSE(cache.predatesEvictedKeys(1006));
    cache.remember(key(1, 4), 1020, T0);                                                    // evicts key 2 (sent 1003); the floor never goes down
    EXPECT_TRUE(cache.predatesEvictedKeys(1005));
}
