#pragma once

#ifndef MESH_HOLE_PUNCH_POLICY_H
#define MESH_HOLE_PUNCH_POLICY_H

#include "meshlink/peer_identity.h"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <vector>

namespace invilite::Mesh {

    // A known peer nobody can dial (no public address, or its public ones failed) that a punch could reach. Only peers
    // with a larger PeerId than ours: the smaller side asks (docs/nat-traversal.md 4).
    struct HolePunchCandidate {
        PeerId                                  peerId{};
        std::chrono::system_clock::time_point   recordCreatedAt{};                  // a fresher record more likely belongs to a node that is up
    };

    // What the policy looks at, gathered by Network
    struct HolePunchSituation {
        bool                            behindNat               = false;            // peers see us at a public address we do not announce
        size_t                          privateLinks            = 0;                // active connections to peers nobody can dial
        size_t                          outboundConnections     = 0;
        size_t                          outboundTarget          = 0;                // what Topology aims for (R10)
        bool                            dialableCandidatesLeft  = false;            // Topology still has someone to dial
        std::vector<HolePunchCandidate> candidates;
    };

    // Whom to punch to now (docs/nat-traversal.md 5), in this order:
    //   (c) a node behind NAT keeps at least `minPrivateLinks` direct links to other such nodes — the mesh that survives
    //       when public servers, the censor's first target, are blocked;
    //   (a) below Topology's target with no dialable candidate left — the rest is reachable only by punching.
    // Freshest record first. Nothing for a node that is not behind NAT: everyone can dial it.
    std::optional<PeerId> chooseHolePunchTarget(const HolePunchSituation& situation, uint16_t minPrivateLinks);

} // namespace invilite::Mesh

#endif // MESH_HOLE_PUNCH_POLICY_H
