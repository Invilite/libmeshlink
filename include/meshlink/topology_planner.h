#pragma once

#ifndef MESH_TOPOLOGY_PLANNER_H
#define MESH_TOPOLOGY_PLANNER_H

#include "meshlink/signed_peer_record.h"
#include "meshlink/peer.h"

#include <chrono>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace invilite::Mesh {

    struct NetworkConfig;                                                               // defined in network.h — forward-declared to avoid circular include

// Snapshot of a single connected peer passed into TopologyPlanner::evaluate().
    struct ConnectedPeerInfo {
        PeerId  peerId;
        bool    isOutbound;
    };

// Peer chosen to dial: who (so the caller can track the attempt per peer) and where — every dialable address, tried in
// order until one answers (F4).
    struct DialTarget {
        PeerId                      peerId;
        std::vector<PeerAddress>    addresses;
    };

// Decision returned by TopologyPlanner::evaluate() for one management tick.
    struct TopologyDecision {
        // One candidate to dial next, if outbound count is below target. nullopt = nothing to do.
        std::optional<DialTarget>                       connectTo;

        // One peer to disconnect, e.g. for connection churn once scoring is available. nullopt for now.
        std::optional<PeerId>                           disconnect;

        // How long the management thread should wait before calling evaluate() again.
        std::chrono::milliseconds                       nextTick;
    };

// Pure topology decision logic — no side effects, no Network state.
// Network calls evaluate() each tick and acts on the returned TopologyDecision.
    class TopologyPlanner {
    public:
        // Evaluate current topology and return one action to take plus next tick interval.
        //
        // `connected`  — all currently active peers
        // `candidates` — Verified peers from knownPeers; caller is responsible for
        //                filtering out self and peers already in `connected`
        TopologyDecision evaluate(const std::vector<ConnectedPeerInfo>& connected,
                                  const std::vector<SignedPeerRecord>&  candidates,
                                  const NetworkConfig&                  config) const;

        // How many outbound connections Topology aims for with these connections (R10)
        static size_t outboundTarget(const std::vector<ConnectedPeerInfo>& connected, const NetworkConfig& config);
    };

} // namespace invilite::Mesh

#endif // MESH_TOPOLOGY_PLANNER_H