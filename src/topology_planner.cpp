#include "meshlink/topology_planner.h"
#include "meshlink/network.h"                                                       // full NetworkConfig definition

#include <algorithm>
#include <random>

namespace invilite::Mesh {

    namespace {
        constexpr auto TICK_NEEDS_PEERS = std::chrono::milliseconds(3000);             // actively building connections
        constexpr auto TICK_WAITING     = std::chrono::milliseconds(10000);            // below target but no candidates yet
        constexpr auto TICK_SATISFIED   = std::chrono::milliseconds(30000);            // outbound target met
    }

    TopologyDecision TopologyPlanner::evaluate(const std::vector<ConnectedPeerInfo>& connected,
                                               const std::vector<SignedPeerRecord>&  candidates,
                                               const NetworkConfig&                  config) const {
        TopologyDecision decision;

        const size_t outboundCount = std::count_if(connected.begin(), connected.end(),
                                                   [](const ConnectedPeerInfo& p) { return p.isOutbound; });
        const size_t inboundCount  = connected.size() - outboundCount;

        // Outbound target (R10): fill up to the healthy total with what inbound does not cover, never below min (we pick
        // those ourselves — eclipse protection) and never above soft. A public node with plenty of inbound keeps only
        // min outbound; a node behind NAT (no inbound) dials up to soft.
        const ConnectionLimits::Outbound& outbound = config.connectionLimits.outbound;
        const size_t uncovered      = config.connectionLimits.total > inboundCount ? config.connectionLimits.total - inboundCount : 0;
        const size_t outboundTarget = std::clamp<size_t>(uncovered, outbound.min, outbound.soft);

        if (outboundCount >= outboundTarget || candidates.empty()) {
            decision.nextTick = (outboundCount >= outboundTarget)
                                ? TICK_SATISFIED
                                : TICK_WAITING;
            return decision;
        }

        // Pick a random candidate — fair distribution, avoids always hammering the same peer.
        // Caller has already excluded self and currently connected peers.
        static thread_local std::mt19937 rng(std::random_device{}());
        std::uniform_int_distribution<size_t> dist(0, candidates.size() - 1);
        const SignedPeerRecord& chosen = candidates[dist(rng)];

        if (!chosen.addresses.empty()) {
            decision.connectTo = DialTarget{ chosen.peerId, chosen.addresses };    // the caller left only dialable ones
        }

        // disconnect remains nullopt until scoring is available (FoundAnother / churn)

        decision.nextTick = decision.connectTo.has_value() ? TICK_NEEDS_PEERS : TICK_WAITING;
        return decision;
    }

} // namespace invilite::Mesh