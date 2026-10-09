#include "meshlink/known_peer_eviction.h"

#include <algorithm>
#include <tuple>

std::optional<invilite::Mesh::PeerId> invilite::Mesh::chooseEvictionVictim(const std::vector<KnownPeer>& entries, const std::vector<PeerId>& connected, const bool incomingRecordIsProven) {
    const KnownPeer* victim = nullptr;

    // Lower key = less valuable; tuple order is the policy order.
    const auto evictionKey = [](const KnownPeer& entry) {
        return std::make_tuple(entry.hasEverConnected,                                  // proven entries last
                               entry.availability != AvailabilityState::Unavailable,     // Unavailable before Unknown
                               -static_cast<int>(entry.consecutiveProbeFailures),        // more failed probes first
                               entry.firstLearnedAt);                                    // waiting longest first
    };

    for (const auto& entry : entries) {
        if (entry.availability == AvailabilityState::Available) continue;
        if (entry.availability == AvailabilityState::Probing)   continue;                // a probe worker will commit its result
        if (entry.hasEverConnected && !incomingRecordIsProven) continue;
        if (std::find(connected.begin(), connected.end(), entry.record.peerId) != connected.end()) continue;
        if (!victim || evictionKey(entry) < evictionKey(*victim)) victim = &entry;
    }

    if (!victim) return std::nullopt;
    return victim->record.peerId;
}
