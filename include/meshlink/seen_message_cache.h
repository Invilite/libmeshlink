#pragma once

#ifndef MESH_SEEN_MESSAGE_CACHE_H
#define MESH_SEEN_MESSAGE_CACHE_H

#include "meshlink/peer_identity.h"

#include <chrono>
#include <cstdint>
#include <deque>
#include <optional>
#include <unordered_set>

namespace invilite::Mesh {

    // Identity of a routed message: msgId is random per sender, so the pair is unique network-wide
    struct RoutedMessageKey {
        PeerId      sender{};
        uint64_t    msgId = 0;

        bool operator==(const RoutedMessageKey&) const = default;
    };

    struct RoutedMessageKeyHash {
        size_t operator()(const RoutedMessageKey& key) const noexcept;
    };

    // Router's duplicate and replay memory (docs/router.md 4.5). A key is remembered for `window` — longer than the
    // accepted timestamp skew in both directions, so a replay is either remembered or rejected by its timestamp.
    // Capacity bounds memory under a flood of distinct messages; when full, the oldest key goes first. Such an early
    // eviction would reopen the door to replays of the forgotten messages, so the cache keeps a floor: the newest sentAt
    // among keys evicted for capacity. A message sent at or before the floor can no longer be judged and must be dropped
    // (under a flood, late-arriving old messages are lost rather than replayable).
    // Not thread-safe: owned by the Router thread.
    class SeenMessageCache {
    public:
        SeenMessageCache(std::chrono::seconds window, size_t capacity);

        [[nodiscard]] bool contains(const RoutedMessageKey& key) const;

        // True when a message with this sentAt may have been forgotten early (capacity eviction) — treat it as seen
        [[nodiscard]] bool predatesEvictedKeys(uint32_t sentAtUnixSeconds) const;

        // Remember `key` (sent at `sentAtUnixSeconds`) as seen at `now` (no-op if already remembered); forgets keys older
        // than the window
        void remember(const RoutedMessageKey& key, uint32_t sentAtUnixSeconds, std::chrono::steady_clock::time_point now);

        [[nodiscard]] size_t size() const { return this->keys.size(); }

    private:
        struct Entry {
            std::chrono::steady_clock::time_point   seenAt;
            uint32_t                                sentAtUnixSeconds = 0;
            RoutedMessageKey                        key;
        };

        std::chrono::seconds                                    window;
        size_t                                                  capacity;
        std::optional<uint32_t>                                 evictedSentAtFloor;     // newest sentAt evicted for capacity
        std::deque<Entry>                                       byAge;              // oldest first — insertion order is age order
        std::unordered_set<RoutedMessageKey, RoutedMessageKeyHash> keys;
    };

} // namespace invilite::Mesh

#endif // MESH_SEEN_MESSAGE_CACHE_H
