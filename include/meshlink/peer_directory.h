#pragma once

#ifndef MESH_PEER_DIRECTORY_H
#define MESH_PEER_DIRECTORY_H

#include "meshlink/peer_identity.h"
#include "meshlink/signed_peer_record.h"

#include <mutex>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <optional>
#include <shared_mutex>
#include <unordered_map>
#include <vector>

namespace invilite::Mesh {

// Hash for PeerId-keyed maps. Lives here because this is the lowest-level header that depends on PeerId.
    struct PeerIDHash {
        size_t operator()(const PeerId& id) const noexcept {
            size_t h;
            std::memcpy(&h, id.data(), sizeof(h));
            return h;
        }
    };

// Whether the peer's announced address works now; can flip back and forth.
// The lasting proof that a peer ever worked is KnownPeer::hasEverConnected.
    enum class AvailabilityState : uint8_t {
        Unknown      = 0,
        Available    = 1,
        Unavailable  = 2,
        Probing      = 3,
    };

// A signed record plus local gossip and reachability state. Callers get copies from findPeer/listPeers and change
// the stored entry only through upsertPeer/mutatePeer.
    struct KnownPeer {
        SignedPeerRecord                            record;
        uint8_t                                     announceCount         = 0;
        std::chrono::steady_clock::time_point       lastAnnouncedAt{};

        // Set once any address of this record yielded a connection or probe. A newer record (later createdAt) resets it,
        // because the address set may have changed.
        bool                                        hasEverConnected      = false;

        AvailabilityState                           availability          = AvailabilityState::Unknown;

        // This peer last connected to us from a public address, so its private addresses are not dialed or probed
        // (dialableAddresses). Cleared when it reaches us from a private address or we reach it at one.
        bool                                        reachedUsOverPublicInternet = false;

        uint8_t                                     consecutiveConnectionFailures = 0;
        std::chrono::steady_clock::time_point       nextConnectionAttemptAt{};
        // GOODBYE(NoSlots) refusals: reachable but full. Counted apart from failures so such a peer is never demoted.
        uint8_t                                     consecutiveNoSlotsRejections  = 0;

        uint8_t                                     consecutiveProbeFailures      = 0;
        std::chrono::steady_clock::time_point       nextProbeAllowedAt{};

        std::chrono::steady_clock::time_point       firstLearnedAt = std::chrono::steady_clock::now();
    };

// Thread-safe storage for known peers; it knows nothing about HELLO, PEX, probing or topology. No reference to internal
// storage escapes a method. Mutators passed to upsertPeer/mutatePeer run under the exclusive lock: they must be short,
// must not block and must not call back into PeerDirectory (deadlock).
    class PeerDirectory {
    public:
        [[nodiscard]] std::optional<KnownPeer> findPeer(const PeerId& id) const;

        // Snapshot copy of all entries.
        [[nodiscard]] std::vector<KnownPeer>   listPeers() const;

        [[nodiscard]] size_t                   size() const;

        // Atomic insert-or-update. The mutator gets the entry (default-constructed when new) and whether it is new;
        // it must fill in a new entry itself.
        template <typename Fn>
        void upsertPeer(const PeerId& id, Fn&& mutator) {
            std::unique_lock lock(this->mutex_);
            const auto [it, inserted] = this->peers_.try_emplace(id);
            mutator(it->second, inserted);
        }

        // Returns true iff the peer existed and the mutator ran.
        template <typename Fn>
        bool mutatePeer(const PeerId& id, Fn&& mutator) {
            std::unique_lock lock(this->mutex_);
            const auto it = this->peers_.find(id);
            if (it == this->peers_.end()) return false;
            mutator(it->second);
            return true;
        }

        void removePeer(const PeerId& id);

    private:
        mutable std::shared_mutex                                  mutex_;
        std::unordered_map<PeerId, KnownPeer, PeerIDHash>          peers_;
    };

} // namespace invilite::Mesh

#endif // MESH_PEER_DIRECTORY_H