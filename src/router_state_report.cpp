#include "meshlink/network.h"
#include "meshlink/router.h"

#include <algorithm>

namespace invilite::Mesh {

using StateReportWire::CounterValue;
using StateReportWire::Counters;
using StateReportWire::StateCounter;
using StateReportWire::StateQuery;
using StateReportWire::StateReport;
using StateReportWire::StateSection;

namespace {
    void addCounter(Counters& counters, StateCounter counter, uint64_t value) {
        counters.push_back(CounterValue{ static_cast<uint16_t>(counter), value });
    }

    bool wants(const StateQuery& query, StateSection section) { return (query.sections & StateReportWire::sectionBit(section)) != 0; }

    template <typename Duration>
    uint32_t clampedMs(Duration duration) {
        const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(duration).count();
        return static_cast<uint32_t>(std::clamp<int64_t>(ms, 0, UINT32_MAX));
    }
}

// Runs on the Router thread: Plumtree, the GRAFT cache and the awaited replies are touched by that thread only.
StateReport Router::buildStateReport(const StateQuery& query) const {
    StateReport report;
    const auto now = std::chrono::steady_clock::now();
    const bool needsNetwork = wants(query, StateSection::Node) || wants(query, StateSection::Neighbors) || wants(query, StateSection::Network);
    const NetworkDiagnostics network = needsNetwork ? this->network.getDiagnostics() : NetworkDiagnostics{};

    if (wants(query, StateSection::Node)) {
        report.node = StateReportWire::NodeState{
            network.nodeName, RouterWire::WIRE_VERSION,
            static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(now - this->constructedAt).count()),
            static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count()),
            this->clockWindowRejections.load(), this->treeRootElection.root() };
    }

    size_t eagerLinks = 0;
    size_t lazyLinks = 0;
    std::vector<StateReportWire::NeighborState> neighbors;
    for (const NetworkDiagnostics::Link& link : network.links) {
        const bool eager = this->plumtree.hasLink(link.peerId) && this->plumtree.isEager(link.peerId);
        ++(eager ? eagerLinks : lazyLinks);
        neighbors.push_back({ link.peerId, link.inbound, eager, static_cast<uint32_t>(std::min<int64_t>(link.connectedFor.count(), UINT32_MAX)),
                              link.bytesSent, link.bytesReceived, static_cast<uint32_t>(std::min<size_t>(link.sendQueueBytes, UINT32_MAX)), link.holePunched });
    }
    if (wants(query, StateSection::Neighbors)) report.neighbors = std::move(neighbors);

    if (wants(query, StateSection::Plumtree)) {
        Counters& counters = report.plumtree.emplace();
        addCounter(counters, StateCounter::IhaveKeysSent, this->announcementsSent.load());
        addCounter(counters, StateCounter::IhaveKeysReceived, this->ihaveKeysReceived.load());
        addCounter(counters, StateCounter::GraftsSent, this->graftsSent.load());
        addCounter(counters, StateCounter::GraftsReceived, this->graftsReceived.load());
        addCounter(counters, StateCounter::PrunesSent, this->prunesSent.load());
        addCounter(counters, StateCounter::PrunesReceived, this->prunesReceived.load());
        addCounter(counters, StateCounter::DuplicatesDropped, this->duplicatesDropped.load());
        addCounter(counters, StateCounter::GraftsForMissing, this->graftsForMissing.load());
        addCounter(counters, StateCounter::BroadcastCacheEntries, this->broadcastCache.size());
        addCounter(counters, StateCounter::MissingMessagesTracked, this->plumtree.missingCount());
        if (needsNetwork) {
            addCounter(counters, StateCounter::EagerLinks, eagerLinks);
            addCounter(counters, StateCounter::LazyLinks, lazyLinks);
        }
    }

    if (wants(query, StateSection::Routes)) {
        StateReportWire::RoutesState& routes = report.routes.emplace();
        routes.offset = query.routeOffset;
        std::lock_guard lock(this->routesMutex);
        routes.destinationCount = static_cast<uint32_t>(this->routes.destinationCount());
        for (const auto& [destination, candidates] : this->routes.destinationsPage(query.routeOffset, query.routeCount)) {
            for (const RouteCandidate& candidate : candidates) {
                routes.routes.push_back({ destination, candidate.via, candidate.hops, static_cast<uint8_t>(candidate.tier()),
                                          candidate.rtt ? std::optional(clampedMs(*candidate.rtt)) : std::nullopt, clampedMs(now - candidate.lastHeardAt) });
            }
        }
    }

    if (wants(query, StateSection::Delivery)) {
        Counters& counters = report.delivery.emplace();
        addCounter(counters, StateCounter::FullMessagesSent, this->fullMessagesSent.load());
        addCounter(counters, StateCounter::Delivered, this->delivered.load());
        addCounter(counters, StateCounter::UnicastForwarded, this->unicastForwarded.load());
        addCounter(counters, StateCounter::RoutedForwarded, this->routedForwarded.load());
        addCounter(counters, StateCounter::LocalFloods, this->localFloods.load());
        addCounter(counters, StateCounter::AcksSent, this->acksSent.load());
        addCounter(counters, StateCounter::AcksReceived, this->acksReceived.load());
        addCounter(counters, StateCounter::AwaitedReplies, this->awaitedReplies.size());
        addCounter(counters, StateCounter::RouteErrorsSent, this->routeErrorsSent.load());
        addCounter(counters, StateCounter::RouteErrorsReceived, this->routeErrorsReceived.load());
        addCounter(counters, StateCounter::ParkedForSenderRecord, this->pendingVerifications.size());
        addCounter(counters, StateCounter::UnknownModeReportsSent, this->unknownModeReportsSent.load());
        addCounter(counters, StateCounter::StateRepliesSent, this->stateRepliesSent.load());
    }

    if (wants(query, StateSection::Network)) {
        StateReportWire::NetworkState& state = report.network.emplace();
        addCounter(state.counters, StateCounter::ActiveInbound, network.activeInbound);
        addCounter(state.counters, StateCounter::ActiveOutbound, network.activeOutbound);
        addCounter(state.counters, StateCounter::InboundSoftLimit, network.limits.inbound.soft);
        addCounter(state.counters, StateCounter::InboundHardLimit, network.limits.inbound.effectiveHard());
        addCounter(state.counters, StateCounter::OutboundSoftLimit, network.limits.outbound.soft);
        addCounter(state.counters, StateCounter::OutboundHardLimit, network.limits.outbound.effectiveHard());
        const size_t registered = network.activeInbound + network.activeOutbound;
        const size_t slotsInUse = network.inboundSlotsInUse + network.outboundSlotsInUse;
        addCounter(state.counters, StateCounter::HandshakesInFlight, slotsInUse > registered ? slotsInUse - registered : 0);
        addCounter(state.counters, StateCounter::NoSlotsRejectionsSent, network.inboundDismissedForNoSlots);
        addCounter(state.counters, StateCounter::KnownPeers, network.knownPeers);
        addCounter(state.counters, StateCounter::KnownUnknown, network.knownByAvailability[static_cast<size_t>(AvailabilityState::Unknown)]);
        addCounter(state.counters, StateCounter::KnownAvailable, network.knownByAvailability[static_cast<size_t>(AvailabilityState::Available)]);
        addCounter(state.counters, StateCounter::KnownUnavailable, network.knownByAvailability[static_cast<size_t>(AvailabilityState::Unavailable)]);
        addCounter(state.counters, StateCounter::KnownProbing, network.knownByAvailability[static_cast<size_t>(AvailabilityState::Probing)]);
        const auto& punching = network.holePunching;
        addCounter(state.counters, StateCounter::HolePunchBehindNat, punching.behindNat ? 1 : 0);
        addCounter(state.counters, StateCounter::HolePunchPrivateLinks, punching.privateLinks);
        addCounter(state.counters, StateCounter::HolePunchesRequested, punching.requested);
        addCounter(state.counters, StateCounter::HolePunchesDeclined, punching.declined);
        addCounter(state.counters, StateCounter::HolePunchesStarted, punching.started);
        addCounter(state.counters, StateCounter::HolePunchesConnected, punching.connected);
        addCounter(state.counters, StateCounter::HolePunchesFailed, punching.failed);
        addCounter(state.counters, StateCounter::HolePunchesCoordinated, punching.coordinated);
        state.observedSelfAddresses = network.observedSelfAddresses;
    }
    return report;
}

} // namespace invilite::Mesh
