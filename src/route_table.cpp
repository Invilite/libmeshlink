#include "meshlink/route_table.h"

#include <algorithm>

namespace invilite::Mesh {

RouteTier RouteCandidate::tier() const {
    if (this->failures > 0) return RouteTier::Failing;
    if (this->rtt)          return RouteTier::Measured;
    if (this->deliveries)   return RouteTier::Delivered;
    return RouteTier::Hinted;
}

namespace {
    // Order: measured (by RTT), delivered, hinted (by hops, then freshness), failing (by failures).
    bool isBetter(const RouteCandidate& a, const RouteCandidate& b) {
        if (a.tier() != b.tier()) return a.tier() < b.tier();
        switch (a.tier()) {
            case RouteTier::Measured: if (*a.rtt != *b.rtt) return *a.rtt < *b.rtt; break;
            case RouteTier::Failing:  if (a.failures != b.failures) return a.failures < b.failures; break;
            default: break;
        }
        if (a.hops != b.hops) return a.hops < b.hops;
        return a.lastHeardAt > b.lastHeardAt;
    }

    std::chrono::milliseconds smoothed(std::chrono::milliseconds previous, std::chrono::milliseconds sample) {
        return (3 * previous + sample) / 4;                                         // EWMA, weight 1/4 for the new sample
    }

    std::vector<RouteCandidate>::iterator findVia(std::vector<RouteCandidate>& candidates, const PeerId& via) {
        return std::find_if(candidates.begin(), candidates.end(), [&](const RouteCandidate& c) { return c.via == via; });
    }
}

RouteTable::RouteTable(RouteTableConfig config) : config(config) {}

RouteTable::Destination* RouteTable::touch(const PeerId& destination, bool create) {
    auto found = this->byDestination.find(destination);
    if (found == this->byDestination.end()) {
        if (!create || this->config.maxDestinations == 0) return nullptr;
        if (this->byDestination.size() >= this->config.maxDestinations) this->eraseDestination(this->byDestination.find(this->leastRecentFirst.front()));
        this->leastRecentFirst.push_back(destination);
        found = this->byDestination.emplace(destination, Destination{ {}, std::prev(this->leastRecentFirst.end()) }).first;
    } else {
        this->leastRecentFirst.splice(this->leastRecentFirst.end(), this->leastRecentFirst, found->second.recency);
    }
    return &found->second;
}

bool RouteTable::admit(Destination& entry, const RouteCandidate& fresh) {
    if (this->config.candidatesPerDestination == 0) return false;
    if (entry.candidates.size() >= this->config.candidatesPerDestination) {
        if (!isBetter(fresh, entry.candidates.back())) return false;
        entry.candidates.pop_back();
    }
    entry.candidates.push_back(fresh);
    return true;
}

void RouteTable::learn(const PeerId& destination, const PeerId& via, uint8_t hops, std::chrono::steady_clock::time_point now) {
    if (hops == 0) return;
    Destination* entry = this->touch(destination, true);
    if (!entry) return;
    if (const auto existing = findVia(entry->candidates, via); existing != entry->candidates.end()) {
        // A hint's hop count is unauthenticated (a relay can lower it), so it never overwrites what a probe recorded.
        if (!existing->rtt) existing->hops = hops;
        existing->lastHeardAt = now;
    } else if (!this->admit(*entry, RouteCandidate{ via, hops, now }) && entry->candidates.empty()) {
        this->eraseDestination(this->byDestination.find(destination));
        return;
    }
    std::sort(entry->candidates.begin(), entry->candidates.end(), isBetter);
}

void RouteTable::recordDelivery(const PeerId& destination, const PeerId& via, std::chrono::steady_clock::time_point now) {
    Destination* entry = this->touch(destination, via == destination);
    if (!entry) return;
    auto existing = findVia(entry->candidates, via);
    if (existing == entry->candidates.end()) {
        if (via != destination || !this->admit(*entry, RouteCandidate{ via, 1, now })) return;
        existing = std::prev(entry->candidates.end());
    }
    ++existing->deliveries;
    existing->failures = 0;
    existing->lastHeardAt = now;
    std::sort(entry->candidates.begin(), entry->candidates.end(), isBetter);
}

void RouteTable::recordMeasurement(const PeerId& destination, const PeerId& via, uint8_t hops, std::chrono::milliseconds rtt, std::chrono::steady_clock::time_point now) {
    if (hops == 0) return;
    Destination* entry = this->touch(destination, true);
    if (!entry) return;
    auto existing = findVia(entry->candidates, via);
    if (existing == entry->candidates.end()) {
        if (!this->admit(*entry, RouteCandidate{ via, hops, now, 0, rtt, now })) return;
        existing = std::prev(entry->candidates.end());
    } else {
        existing->rtt = existing->rtt ? smoothed(*existing->rtt, rtt) : rtt;
    }
    existing->hops       = hops;                                                    // as the probe recorded it, which is better than a TTL hint
    existing->measuredAt = now;
    existing->failures   = 0;
    existing->lastHeardAt = now;
    std::sort(entry->candidates.begin(), entry->candidates.end(), isBetter);
}

void RouteTable::recordFailure(const PeerId& destination, const PeerId& via) {
    const auto found = this->byDestination.find(destination);
    if (found == this->byDestination.end()) return;
    auto& candidates = found->second.candidates;
    const auto existing = findVia(candidates, via);
    if (existing == candidates.end()) return;
    if (++existing->failures >= this->config.failuresToForget) candidates.erase(existing);
    if (candidates.empty()) { this->eraseDestination(found); return; }
    std::sort(candidates.begin(), candidates.end(), isBetter);
}

std::vector<PeerId> RouteTable::nextHops(const PeerId& destination, const std::optional<PeerId>& excluded) const {
    std::vector<PeerId> hops;
    const auto found = this->byDestination.find(destination);
    if (found == this->byDestination.end()) return hops;
    for (const RouteCandidate& candidate : found->second.candidates) {
        if (candidate.via != excluded) hops.push_back(candidate.via);
    }
    return hops;
}

std::vector<RouteCandidate> RouteTable::candidates(const PeerId& destination) const {
    const auto found = this->byDestination.find(destination);
    return found == this->byDestination.end() ? std::vector<RouteCandidate>{} : found->second.candidates;
}

std::vector<std::pair<PeerId, std::vector<RouteCandidate>>> RouteTable::destinationsPage(size_t offset, size_t count) const {
    std::vector<PeerId> destinations;
    destinations.reserve(this->byDestination.size());
    for (const auto& [destination, entry] : this->byDestination) destinations.push_back(destination);
    std::sort(destinations.begin(), destinations.end());

    std::vector<std::pair<PeerId, std::vector<RouteCandidate>>> page;
    for (size_t i = offset; i < destinations.size() && page.size() < count; ++i) page.emplace_back(destinations[i], this->byDestination.at(destinations[i]).candidates);
    return page;
}

void RouteTable::forgetNeighbor(const PeerId& via) {
    for (auto it = this->byDestination.begin(); it != this->byDestination.end();) {
        std::erase_if(it->second.candidates, [&](const RouteCandidate& c) { return c.via == via; });
        if (it->second.candidates.empty()) {
            this->leastRecentFirst.erase(it->second.recency);
            it = this->byDestination.erase(it);
        } else {
            ++it;
        }
    }
}

void RouteTable::forgetRoute(const PeerId& destination, const PeerId& via) {
    const auto found = this->byDestination.find(destination);
    if (found == this->byDestination.end()) return;
    std::erase_if(found->second.candidates, [&](const RouteCandidate& c) { return c.via == via; });
    if (found->second.candidates.empty()) this->eraseDestination(found);
}

void RouteTable::eraseDestination(Destinations::iterator entry) {
    this->leastRecentFirst.erase(entry->second.recency);
    this->byDestination.erase(entry);
}

} // namespace invilite::Mesh
