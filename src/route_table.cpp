#include "meshlink/route_table.h"

#include <algorithm>

namespace invilite::Mesh {

namespace {
    // Ranking of docs/router.md 4.4: ACK-confirmed first, then fewer hops, lower RTT (unknown last), most recent
    bool isBetter(const RouteCandidate& a, const RouteCandidate& b) {
        if (a.evidence != b.evidence) return a.evidence == RouteEvidence::Ack;
        if (a.hops != b.hops) return a.hops < b.hops;
        if (a.rtt.has_value() != b.rtt.has_value()) return a.rtt.has_value();
        if (a.rtt && *a.rtt != *b.rtt) return *a.rtt < *b.rtt;
        return a.lastConfirmedAt > b.lastConfirmedAt;
    }

    std::chrono::milliseconds smoothed(std::chrono::milliseconds previous, std::chrono::milliseconds sample) {
        return (3 * previous + sample) / 4;                                         // EWMA, weight 1/4 for the new sample
    }
}

RouteTable::RouteTable(RouteTableConfig config) : config(config) {}

void RouteTable::learn(const PeerId& destination, const PeerId& via, uint8_t hops, RouteEvidence evidence, std::chrono::steady_clock::time_point now,
                       std::optional<std::chrono::milliseconds> rtt) {
    if (hops == 0 || this->config.candidatesPerDestination == 0 || this->config.maxDestinations == 0) return;

    auto found = this->byDestination.find(destination);
    if (found == this->byDestination.end()) {
        if (this->byDestination.size() >= this->config.maxDestinations) this->eraseDestination(this->byDestination.find(this->leastRecentFirst.front()));
        this->leastRecentFirst.push_back(destination);
        found = this->byDestination.emplace(destination, Destination{ {}, std::prev(this->leastRecentFirst.end()) }).first;
    } else {
        this->leastRecentFirst.splice(this->leastRecentFirst.end(), this->leastRecentFirst, found->second.recency);   // heard of it now
    }

    auto& candidates = found->second.candidates;
    const auto existing = std::find_if(candidates.begin(), candidates.end(), [&](const RouteCandidate& c) { return c.via == via; });
    if (existing != candidates.end()) {
        // Newer data replaces — except that a broadcast's hop count (unsigned, a relay can lower it) never rewrites an
        // ACK-confirmed candidate (review R-5 M1)
        if (evidence == RouteEvidence::Ack || existing->evidence != RouteEvidence::Ack) existing->hops = hops;
        existing->lastConfirmedAt = now;
        if (evidence == RouteEvidence::Ack) existing->evidence = RouteEvidence::Ack;
        if (rtt) existing->rtt = existing->rtt ? smoothed(*existing->rtt, *rtt) : *rtt;
    } else {
        const RouteCandidate fresh{ via, hops, evidence, now, rtt };
        if (candidates.size() >= this->config.candidatesPerDestination) {
            if (!isBetter(fresh, candidates.back())) return;                        // the known ones are all at least as good
            candidates.pop_back();
        }
        candidates.push_back(fresh);
    }
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

void RouteTable::eraseDestination(std::unordered_map<PeerId, Destination, PeerIDHash>::iterator entry) {
    this->leastRecentFirst.erase(entry->second.recency);
    this->byDestination.erase(entry);
}

} // namespace invilite::Mesh
