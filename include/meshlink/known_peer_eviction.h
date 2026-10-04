#pragma once

#ifndef MESH_KNOWN_PEER_EVICTION_H
#define MESH_KNOWN_PEER_EVICTION_H

#include "meshlink/peer_directory.h"

#include <optional>
#include <vector>

namespace invilite::Mesh {

// Address book eviction policy (roadmap R2) — discovery's decision, not PeerDirectory's (storage knows no protocol).
// When the book is full and a new record arrives, the least valuable entry may make room:
//   - never evicted: connected peers, Available peers, peers being probed right now;
//   - first: Unavailable entries, most failed probes first;
//   - then: Unknown entries that have waited longest for a probe (oldest firstLearnedAt);
//   - entries with hasEverConnected go last, and only for a record that is itself proven — an unverified newcomer gets a
//     chance against other unverified entries but never pushes out one that once worked.
// Returns nullopt when nothing may be evicted: the new record is then dropped.
std::optional<PeerId> chooseEvictionVictim(const std::vector<KnownPeer>& entries, const std::vector<PeerId>& connected, bool incomingRecordIsProven);

} // namespace invilite::Mesh

#endif // MESH_KNOWN_PEER_EVICTION_H
