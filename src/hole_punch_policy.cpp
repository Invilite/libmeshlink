#include "meshlink/hole_punch_policy.h"

#include <algorithm>

namespace invilite::Mesh {

std::optional<PeerId> chooseHolePunchTarget(const HolePunchSituation& situation, const uint16_t minPrivateLinks) {
    if (!situation.behindNat || situation.candidates.empty()) return std::nullopt;

    const bool needsPrivateLinks = situation.privateLinks < minPrivateLinks;
    const bool belowTarget       = situation.outboundConnections < situation.outboundTarget && !situation.dialableCandidatesLeft;
    if (!needsPrivateLinks && !belowTarget) return std::nullopt;

    const auto freshest = std::max_element(situation.candidates.begin(), situation.candidates.end(),
                                           [](const HolePunchCandidate& a, const HolePunchCandidate& b) { return a.recordCreatedAt < b.recordCreatedAt; });
    return freshest->peerId;
}

} // namespace invilite::Mesh
