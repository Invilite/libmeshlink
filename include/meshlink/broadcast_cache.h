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

    // Recently accepted BROADCAST messages, kept so a neighbor's GRAFT can be answered. Holds each message as received
    // (TTL included) and the neighbors that already got a full copy from us; each gets it at most once, so repeated
    // GRAFTs cannot multiply traffic. Bounded by age and total encoded bytes, oldest first.
    // Not thread-safe: owned by the Router thread.
    class BroadcastCache {
    public:
        BroadcastCache(std::chrono::seconds retention, size_t byteLimit);

        // Keep `message` (first copy wins; false when already held or larger than the whole limit). Drops what is too old
        // or does not fit.
        bool store(RoutedMessage message, std::chrono::steady_clock::time_point now);

        // Swap the held copy for a better one (higher TTL). Neighbors are sent the new copy again, so the record of who
        // got it is cleared. False when the message is not held or the copy does not fit.
        bool replace(RoutedMessage message, std::chrono::steady_clock::time_point now);

        [[nodiscard]] const RoutedMessage* find(const RoutedMessageKey& key) const;

        // Record that `neighbor` has the full copy, after a successful send or because the copy came from it. False when
        // already recorded or the message is not held. Recording before the send would turn a refused send (full queue)
        // into a neighbor that is never served, not even on GRAFT.
        bool markSentTo(const RoutedMessageKey& key, const PeerId& neighbor);
        [[nodiscard]] bool wasSentTo(const RoutedMessageKey& key, const PeerId& neighbor) const;

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
