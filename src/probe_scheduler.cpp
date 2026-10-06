#include "meshlink/probe_scheduler.h"

#include <algorithm>
#include <limits>

namespace invilite::Mesh {

ProbeScheduler::ProbeScheduler(ProbeSchedulerConfig config) : config(config) {}

void ProbeScheduler::noteTraffic(const PeerId& destination, std::chrono::steady_clock::time_point now) {
    this->lastTrafficAt[destination] = now;
    this->recentTraffic.push_back(now);
    while (!this->recentTraffic.empty() && now - this->recentTraffic.front() > this->config.trafficWindow) this->recentTraffic.pop_front();
}

void ProbeScheduler::noteUrgent(const PeerId& destination) {
    if (std::find(this->urgent.begin(), this->urgent.end(), destination) == this->urgent.end()) this->urgent.push_back(destination);
}

void ProbeScheduler::noteProbeFinished(const PeerId& destination, const PeerId& via) {
    this->inFlight.erase(Probe{ destination, via });
}

std::vector<PeerId> ProbeScheduler::activeDestinations(std::chrono::steady_clock::time_point now) const {
    std::vector<PeerId> active;
    for (const auto& [destination, at] : this->lastTrafficAt) if (now - at < this->config.activeWindow) active.push_back(destination);
    return active;
}

bool ProbeScheduler::isLowTraffic(std::chrono::steady_clock::time_point now) const {
    size_t recent = 0;
    for (const auto& at : this->recentTraffic) if (now - at <= this->config.trafficWindow) ++recent;
    const double seconds = std::chrono::duration<double>(this->config.trafficWindow).count();
    return static_cast<double>(recent) / seconds < this->config.lowTrafficMessagesPerSecond;
}

bool ProbeScheduler::isInFlight(const Probe& probe) const {
    return this->inFlight.contains(probe);
}

// A token bucket: probesPerSecond, at most one second's worth saved up
void ProbeScheduler::refill(std::chrono::steady_clock::time_point now) {
    if (!this->refilledAt) {
        this->tokens = this->config.probesPerSecond;
    } else {
        this->tokens = std::min(this->config.probesPerSecond, this->tokens + std::chrono::duration<double>(now - *this->refilledAt).count() * this->config.probesPerSecond);
    }
    this->refilledAt = now;
}

void ProbeScheduler::collectDue(const PeerId& destination, const RouteTable& routes, std::chrono::steady_clock::time_point now,
                                std::chrono::milliseconds interval, std::vector<Probe>& out) const {
    std::vector<std::pair<std::chrono::steady_clock::time_point, Probe>> due;
    for (const RouteCandidate& candidate : routes.candidates(destination)) {
        const Probe probe{ destination, candidate.via };
        if (this->isInFlight(probe) || std::find(out.begin(), out.end(), probe) != out.end()) continue;
        if (candidate.measuredAt && now - *candidate.measuredAt < interval) continue;
        due.emplace_back(candidate.measuredAt.value_or(std::chrono::steady_clock::time_point::min()), probe);
    }
    std::sort(due.begin(), due.end(), [](const auto& a, const auto& b) { return a.first < b.first; });   // never measured, then oldest
    for (const auto& [at, probe] : due) out.push_back(probe);
}

std::vector<ProbeScheduler::Probe> ProbeScheduler::takeDueProbes(std::chrono::steady_clock::time_point now, const RouteTable& routes) {
    if (!this->config.enabled) return {};
    std::erase_if(this->inFlight, [&](const auto& entry) { return now - entry.second >= this->config.probeTimeout; });
    std::erase_if(this->lastTrafficAt, [&](const auto& entry) { return now - entry.second >= this->config.activeWindow; });
    this->refill(now);
    const auto budget = static_cast<size_t>(this->tokens);
    if (budget == 0) return {};

    // Candidates in priority order: urgent, active, background — then cut to the budget
    std::vector<Probe> wanted;
    while (!this->urgent.empty() && wanted.size() < budget) {
        this->collectDue(this->urgent.front(), routes, now, std::chrono::milliseconds(0), wanted);
        this->urgent.pop_front();
    }
    std::vector<std::pair<std::chrono::steady_clock::time_point, PeerId>> active;
    for (const auto& [destination, at] : this->lastTrafficAt) active.emplace_back(at, destination);
    std::sort(active.begin(), active.end(), [](const auto& a, const auto& b) { return a.first > b.first; });   // most recent traffic first
    for (const auto& [at, destination] : active) {
        if (wanted.size() >= budget) break;
        this->collectDue(destination, routes, now, this->config.activeProbeInterval, wanted);
    }
    // The background scan reads the whole table: once a second at most, and only while traffic is low
    if (wanted.size() < budget && this->isLowTraffic(now) && (!this->backgroundScannedAt || now - *this->backgroundScannedAt >= std::chrono::seconds(1))) {
        this->backgroundScannedAt = now;
        std::vector<std::pair<std::chrono::steady_clock::time_point, Probe>> background;
        for (const auto& [destination, candidates] : routes.destinationsPage(0, std::numeric_limits<size_t>::max())) {
            for (const RouteCandidate& candidate : candidates) {
                const Probe probe{ destination, candidate.via };
                if (this->isInFlight(probe) || std::find(wanted.begin(), wanted.end(), probe) != wanted.end()) continue;
                if (candidate.measuredAt && now - *candidate.measuredAt < this->config.backgroundProbeInterval) continue;
                background.emplace_back(candidate.measuredAt.value_or(std::chrono::steady_clock::time_point::min()), probe);
            }
        }
        std::sort(background.begin(), background.end(), [](const auto& a, const auto& b) { return a.first < b.first; });
        for (const auto& [at, probe] : background) wanted.push_back(probe);
    }

    if (wanted.size() > budget) wanted.resize(budget);
    this->tokens -= static_cast<double>(wanted.size());
    for (const Probe& probe : wanted) this->inFlight.emplace(probe, now);
    return wanted;
}

} // namespace invilite::Mesh
