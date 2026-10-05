#pragma once

#ifndef MESH_BROADCAST_CACHE_H
#define MESH_BROADCAST_CACHE_H

#include "meshlink/peer_directory.h"
#include "meshlink/routed_message_key.h"
#include "meshlink/router_wire.h"

#include <chrono>
#include <list>
#include <unordered_map>
#include <unordered_set>

namespace invilite::Mesh {

    // Recently accepted BROADCAST messages, kept so a neighbor's GRAFT can be answered (docs/router.md 4.3). Holds each
    // message as received (TTL included) and, per message, the neighbors that already got a full copy from us — each gets
    // it at most once, so repeated GRAFTs cannot multiply traffic. Bounded by age and total encoded bytes; the oldest
    // message goes first. Pure storage: whom to send to is the Plumtree logic's decision.
    // Not thread-safe: owned by the Router thread.
    class BroadcastCache {
    public:
        BroadcastCache(std::chrono::seconds retention, size_t byteLimit);

        // Keep `message` (first copy wins; false when already held or larger than the whole limit). Drops what is too old
        // or does not fit.
        bool store(RoutedMessage message, std::chrono::steady_clock::time_point now);

        // Swap the held copy for a better one (higher TTL) — the neighbors are sent the new copy again, so the record of
        // who got it is cleared. False when the message is not held or the copy does not fit.
        bool replace(RoutedMessage message, std::chrono::steady_clock::time_point now);

        [[nodiscard]] const RoutedMessage* find(const RoutedMessageKey& key) const;

        // Record that `neighbor` gets the full copy now; false when it already got it from us (or the message is not held)
        bool markSentTo(const RoutedMessageKey& key, const PeerId& neighbor);

        // A neighbor that left may not have received what was queued to it: it can be sent everything again
        void forgetNeighbor(const PeerId& neighbor);

        void dropExpired(std::chrono::steady_clock::time_point now);

        [[nodiscard]] size_t size() const { return this->byKey.size(); }
        [[nodiscard]] size_t bytes() const { return this->totalBytes; }

    private:
        struct Entry {
            RoutedMessage                           message;
            size_t                                  encodedBytes = 0;
            std::chrono::steady_clock::time_point   storedAt;
            std::unordered_set<PeerId, PeerIDHash>  sentTo;
        };
        using EntryList = std::list<Entry>;

        void makeRoom(size_t bytesNeeded);
        void erase(EntryList::iterator entry);

        std::chrono::seconds                                                    retention;
        size_t                                                                  byteLimit;
        size_t                                                                  totalBytes = 0;
        EntryList                                                               byAge;      // oldest first
        std::unordered_map<RoutedMessageKey, EntryList::iterator, RoutedMessageKeyHash> byKey;
    };

} // namespace invilite::Mesh

#endif // MESH_BROADCAST_CACHE_H
