#include <gtest/gtest.h>
#include "meshlink/connection_slots.h"

#include <thread>
#include <vector>

using namespace invilite::Mesh;

TEST(ConnectionSlotsTest, InboundHardLimitRefusesUntilSlotReturns) {
    ConnectionSlots slots;
    std::vector<ConnectionSlots::Slot> held;
    for (int i = 0; i < 3; ++i) {
        auto slot = slots.tryTakeInbound("10.0.0." + std::to_string(i), 3, 5);
        ASSERT_TRUE(slot.has_value());
        held.push_back(std::move(*slot));
    }
    EXPECT_FALSE(slots.inboundHasRoom(3));
    EXPECT_FALSE(slots.tryTakeInbound("10.0.0.9", 3, 5).has_value());

    held.pop_back();
    EXPECT_TRUE(slots.inboundHasRoom(3));
    EXPECT_TRUE(slots.tryTakeInbound("10.0.0.9", 3, 5).has_value());
}

TEST(ConnectionSlotsTest, PerAddressLimitAppliesToOneAddressOnly) {
    ConnectionSlots slots;
    std::vector<ConnectionSlots::Slot> held;
    for (int i = 0; i < 2; ++i) held.push_back(std::move(*slots.tryTakeInbound("192.0.2.1", 10, 2)));

    EXPECT_FALSE(slots.tryTakeInbound("192.0.2.1", 10, 2).has_value());
    EXPECT_TRUE(slots.tryTakeInbound("192.0.2.2", 10, 2).has_value());
}

// Slots are released exactly once on every path: destruction, move-assignment over a held slot, moved-from objects.
// A leak would lock the node out after enough failures; a double release would let it exceed the hard limit.
TEST(ConnectionSlotsTest, SlotIsReleasedExactlyOnce) {
    ConnectionSlots slots;
    {
        auto first  = slots.tryTakeInbound("192.0.2.1", 10, 10);
        auto second = slots.tryTakeInbound("192.0.2.1", 10, 10);
        ASSERT_EQ(slots.inboundInUse(), 2u);

        ConnectionSlots::Slot moved = std::move(*first);                                  // moved-from must not release
        EXPECT_EQ(slots.inboundInUse(), 2u);
        moved = std::move(*second);                                                       // overwriting releases the old one
        EXPECT_EQ(slots.inboundInUse(), 1u);
    }
    EXPECT_EQ(slots.inboundInUse(), 0u);
    EXPECT_TRUE(slots.tryTakeInbound("192.0.2.1", 10, 1).has_value()) << "per-address count leaked";
}

TEST(ConnectionSlotsTest, OutboundHardLimitIsIndependentOfInbound) {
    ConnectionSlots slots;
    auto inbound = slots.tryTakeInbound("192.0.2.1", 1, 1);
    auto first   = slots.tryTakeOutbound(2);
    auto second  = slots.tryTakeOutbound(2);
    ASSERT_TRUE(inbound && first && second);
    EXPECT_FALSE(slots.tryTakeOutbound(2).has_value());
    EXPECT_EQ(slots.outboundInUse(), 2u);
}

// Accept thread, handshake workers and the I/O thread take and return slots concurrently; the limit must hold.
TEST(ConnectionSlotsTest, LimitHoldsUnderConcurrentTakeAndRelease) {
    ConnectionSlots slots;
    std::atomic<size_t> maxSeen{0};
    std::vector<std::thread> threads;
    for (int t = 0; t < 8; ++t) {
        threads.emplace_back([&, t] {
            for (int i = 0; i < 2000; ++i) {
                auto slot = slots.tryTakeInbound("198.51.100." + std::to_string(t % 3), 5, 3);
                const size_t inUse = slots.inboundInUse();
                size_t seen = maxSeen.load();
                while (inUse > seen && !maxSeen.compare_exchange_weak(seen, inUse)) {}
            }
        });
    }
    for (auto& thread : threads) thread.join();
    EXPECT_LE(maxSeen.load(), 5u);
    EXPECT_EQ(slots.inboundInUse(), 0u);
}
