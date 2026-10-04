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

// Hash specialization for PeerId — used by both PeerDirectory and Network's connected-peer maps.
// Lives here because this is the lowest-level header that depends on PeerId and is included
// wherever PeerId-keyed maps are needed.
    struct PeerIDHash {
        size_t operator()(const PeerId& id) const noexcept {
            size_t h;
            std::memcpy(&h, id.data(), sizeof(h));
            return h;
        }
    };

// Current availability of a known peer — does the peer's announced address work *now*?
// Present-time signal; can flip back and forth as conditions change.
// Persistent "we have proof this peer ever worked" lives in KnownPeer::hasEverConnected.
    enum class AvailabilityState : uint8_t {
        Unknown      = 0,                                                                   // No evidence — never tried, or previous evidence invalidated by a fresher record.
        Available    = 1,                                                                   // Last attempt or probe succeeded — reachable right now.
        Unavailable  = 2,                                                                   // Last attempt or probe failed — do not retry without backoff.
        Probing      = 3,                                                                   // Probe worker in flight; will resolve to Available or Unavailable.
    };

// Bookkeeping for a known peer — wraps the signed record with local gossip and reachability state.
// Owned by PeerDirectory. Callers receive copies via findPeer/listPeers and mutate in-place via
// upsertPeer/mutatePeer (both run the supplied lambda under the directory's exclusive lock).
    struct KnownPeer {
        SignedPeerRecord                            record;
        uint8_t                                     announceCount         = 0;
        std::chrono::steady_clock::time_point       lastAnnouncedAt{};

        // True until first PEX_ANNOUNCE flood. Distinguishes fresh arrivals from records already in circulation.
        bool                                        pendingPexBroadcast   = true;

        // Persistent flag — has any address in this record's address set ever yielded a successful connection
        // or probe? Once true, stays true until replaced by a newer record version (createdAt >), which
        // resets it because the address set may have changed.
        bool                                        hasEverConnected      = false;

        // Current reachability — see AvailabilityState. Independent from hasEverConnected.
        AvailabilityState                           availability          = AvailabilityState::Unknown;

        // ── Connection attempt backoff (TopologyPlanner domain) ──
        uint8_t                                     consecutiveConnectionFailures = 0;
        std::chrono::steady_clock::time_point       nextConnectionAttemptAt{};

        // ── Probe backoff (Network/probe domain) ──
        uint8_t                                     consecutiveProbeFailures      = 0;
        std::chrono::steady_clock::time_point       nextProbeAllowedAt{};

        std::chrono::steady_clock::time_point       firstLearnedAt = std::chrono::steady_clock::now();
    };

// Thread-safe storage for known peers. Pure data layer:
//   - No knowledge of HELLO, PEX, probe, topology — those policies live in the caller.
//   - All operations take their own lock (shared for reads, exclusive for writes) and release before
//     returning. No reference to internal storage ever escapes a method.
//   - Mutator lambdas in upsertPeer/mutatePeer run under the exclusive lock — they MUST be short,
//     non-blocking, and MUST NOT call back into PeerDirectory (would deadlock).
    class PeerDirectory {
    public:
        // ── Read ──
        [[nodiscard]] std::optional<KnownPeer> findPeer(const PeerId& id) const;

        // Snapshot — safe to iterate after the call returns. Copies all entries.
        [[nodiscard]] std::vector<KnownPeer>   listPeers() const;

        [[nodiscard]] size_t                   size() const;

        // ── Write ──
        // Atomic insert-or-update. Mutator runs under exclusive lock with:
        //   - reference to the entry (default-constructed if newly created),
        //   - bool indicating whether this is a fresh entry (true) or an existing one (false).
        // Caller is responsible for populating fields appropriately on a new entry.
        template <typename Fn>
        void upsertPeer(const PeerId& id, Fn&& mutator) {
            std::unique_lock lock(this->mutex_);
            const auto [it, inserted] = this->peers_.try_emplace(id);
            mutator(it->second, inserted);
        }

        // Mutate only if the peer already exists. Returns true iff mutator was invoked.
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