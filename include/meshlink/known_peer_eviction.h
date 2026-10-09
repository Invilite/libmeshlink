#pragma once

#ifndef MESH_KNOWN_PEER_EVICTION_H
#define MESH_KNOWN_PEER_EVICTION_H

#include "meshlink/peer_directory.h"

#include <optional>
#include <vector>

namespace invilite::Mesh {

// Picks the entry that makes room for a new record when the address book is full. Never evicts connected, Available or
// Probing peers; Unavailable entries go first (most failed probes), then the oldest Unknown. Entries with hasEverConnected
// go last, and only for an incoming record that is itself proven, so an unverified newcomer never pushes out a peer that
// once worked. Returns nullopt when nothing may be evicted: the new record is then dropped.
std::optional<PeerId> chooseEvictionVictim(const std::vector<KnownPeer>& entries, const std::vector<PeerId>& connected, bool incomingRecordIsProven);

} // namespace invilite::Mesh

#endif // MESH_KNOWN_PEER_EVICTION_H
