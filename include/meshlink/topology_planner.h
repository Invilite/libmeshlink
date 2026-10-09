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

    struct NetworkConfig;                                                               // defined in network.h (avoids a circular include)

    struct ConnectedPeerInfo {
        PeerId  peerId;
        bool    isOutbound;
    };

// Peer chosen to dial: who (so the caller can track the attempt per peer) and where: every dialable address, tried in
// order until one answers.
    struct DialTarget {
        PeerId                      peerId;
        std::vector<PeerAddress>    addresses;
    };

    struct TopologyDecision {
        // One candidate to dial next, if outbound count is below target. nullopt = nothing to do.
        std::optional<DialTarget>                       connectTo;

        // Always nullopt for now; reserved for dropping a peer once scoring exists.
        std::optional<PeerId>                           disconnect;

        std::chrono::milliseconds                       nextTick;
    };

// Pure topology decision logic: no side effects, no Network state. Called from the management thread each tick.
    class TopologyPlanner {
    public:
        // Returns at most one action plus the interval until the next tick.
        // `connected` is all currently active peers; `candidates` are Verified peers, and the caller must already have
        // filtered out self and peers in `connected`.
        TopologyDecision evaluate(const std::vector<ConnectedPeerInfo>& connected,
                                  const std::vector<SignedPeerRecord>&  candidates,
                                  const NetworkConfig&                  config) const;

        // How many outbound connections Topology aims for given the current connections.
        static size_t outboundTarget(const std::vector<ConnectedPeerInfo>& connected, const NetworkConfig& config);
    };

} // namespace invilite::Mesh

#endif // MESH_TOPOLOGY_PLANNER_H