#pragma once

#ifndef MESH_TREE_ROOT_ELECTION_H
#define MESH_TREE_ROOT_ELECTION_H

#include "meshlink/peer_identity.h"

#include <chrono>
#include <cstddef>
#include <optional>
#include <vector>

namespace invilite::Mesh {

    struct TreeRootConfig {
        // Off: no beacons, and every broadcast shapes the tree (classic Plumtree: fine with one sender, oscillates with
        // several at once); only for tests that count traffic exactly
        bool                        enabled             = true;
        std::chrono::milliseconds   beaconInterval      = std::chrono::seconds(10);    // the root's TREE_BEACON period; also how long repairs may leave cycles uncut
        size_t                      missedBeaconsToLose = 3;
    };

    // A change worth logging
    struct TreeRootChange {
        enum class Kind {
            Claimed,
            Adopted,                                                        // `root` is the root now (`previous`: the one before, if any)
            Lost,
            Yielded,
        };
        Kind                    kind = Kind::Adopted;
        std::optional<PeerId>   root;
        std::optional<PeerId>   previous;
    };

    // Which node shapes the shared Plumtree tree: the smallest PeerId heard sending TREE_BEACON recently. A node that hears
    // none smaller than itself claims the role after a random listening time (after start and after the root was lost),
    // so that only about ln N nodes claim at once and all but the smallest yield within a beacon period.
    // Decides only: the Router sends beacons, feeds received ones and asks root() before a PRUNE. Not thread-safe: owned by
    // the Router thread. Time comes in as `now`; the listening time is drawn by the caller (tests pick it).
    class TreeRootElection {
    public:
        TreeRootElection(const PeerId& self, TreeRootConfig config);

        // Starts listening now; claims at `now + listenFor` unless a smaller node's beacon arrives first
        void start(std::chrono::steady_clock::time_point now, std::chrono::milliseconds listenFor);

        // A verified TREE_BEACON from `sender` (counted only when its TTL reaches as far as ours; the caller checks)
        std::vector<TreeRootChange> onBeacon(const PeerId& sender, std::chrono::steady_clock::time_point now);

        // Expiry, claiming and the beacon timer. `listenAfterLoss` is used when the root is lost now (drawn by the caller).
        // sendBeacon: this node is the root and its beacon is due.
        struct TickResult {
            std::vector<TreeRootChange> changes;
            bool                        sendBeacon = false;
        };
        TickResult tick(std::chrono::steady_clock::time_point now, std::chrono::milliseconds listenAfterLoss);

        // The node whose messages may shape the tree; nothing before any beacon was heard or sent
        [[nodiscard]] std::optional<PeerId> root() const;
        [[nodiscard]] bool isRoot() const { return this->claiming; }

        // Earliest moment tick() has something to do
        [[nodiscard]] std::optional<std::chrono::steady_clock::time_point> nextDeadline() const;

    private:
        [[nodiscard]] std::chrono::steady_clock::time_point expiresAt() const;

        const PeerId                                            self;
        const TreeRootConfig                                    config;
        bool                                                    started = false;
        bool                                                    claiming = false;
        std::optional<PeerId>                                   heardRoot;          // smallest id with a recent beacon (not us)
        std::chrono::steady_clock::time_point                   heardAt{};
        std::optional<std::chrono::steady_clock::time_point>    claimAt;            // listening until then
        std::chrono::steady_clock::time_point                   nextBeaconAt{};
    };

} // namespace invilite::Mesh

#endif // MESH_TREE_ROOT_ELECTION_H
