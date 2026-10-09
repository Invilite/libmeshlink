#pragma once

#ifndef MESH_PROBE_SCHEDULER_H
#define MESH_PROBE_SCHEDULER_H

#include "meshlink/route_table.h"

#include <chrono>
#include <cstddef>
#include <deque>
#include <map>
#include <optional>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace invilite::Mesh {

    struct ProbeSchedulerConfig {
        bool                        enabled                     = true;
        double                      probesPerSecond             = 5;
        std::chrono::milliseconds   activeWindow                = std::chrono::seconds(60);
        std::chrono::milliseconds   activeProbeInterval         = std::chrono::seconds(30);
        std::chrono::milliseconds   backgroundProbeInterval     = std::chrono::minutes(10);
        double                      lowTrafficMessagesPerSecond = 10;
        std::chrono::milliseconds   trafficWindow               = std::chrono::seconds(10);
        std::chrono::milliseconds   probeTimeout                = std::chrono::seconds(5);
    };

    // Decides which routes to measure next: urgent ones first, then routes of active destinations, then the background
    // (only while traffic is low), under a hard probesPerSecond limit and one probe in flight per (destination, neighbor).
    // The Router sends the probes. Not thread-safe: owned by the Router thread.
    class ProbeScheduler {
    public:
        explicit ProbeScheduler(ProbeSchedulerConfig config = {});

        struct Probe {
            PeerId  destination{};
            PeerId  via{};
            bool operator==(const Probe&) const = default;
        };

        void noteTraffic(const PeerId& destination, std::chrono::steady_clock::time_point now);
        void noteUrgent(const PeerId& destination);
        void noteProbeFinished(const PeerId& destination, const PeerId& via);

        [[nodiscard]] std::vector<PeerId> activeDestinations(std::chrono::steady_clock::time_point now) const;

        // Marks each returned probe as in flight.
        std::vector<Probe> takeDueProbes(std::chrono::steady_clock::time_point now, const RouteTable& routes);

    private:
        [[nodiscard]] bool isLowTraffic(std::chrono::steady_clock::time_point now) const;
        [[nodiscard]] bool isInFlight(const Probe& probe) const;
        void refill(std::chrono::steady_clock::time_point now);
        void collectDue(const PeerId& destination, const RouteTable& routes, std::chrono::steady_clock::time_point now,
                        std::chrono::milliseconds interval, std::vector<Probe>& out) const;

        struct ProbeHash { size_t operator()(const Probe& p) const { return PeerIDHash{}(p.destination) ^ (PeerIDHash{}(p.via) << 1); } };

        ProbeSchedulerConfig                                                    config;
        double                                                                  tokens = 0;
        std::optional<std::chrono::steady_clock::time_point>                    refilledAt;
        std::unordered_map<PeerId, std::chrono::steady_clock::time_point, PeerIDHash> lastTrafficAt;
        std::deque<std::chrono::steady_clock::time_point>                       recentTraffic;
        std::deque<PeerId>                                                      urgent;
        std::unordered_map<Probe, std::chrono::steady_clock::time_point, ProbeHash> inFlight;
        std::optional<std::chrono::steady_clock::time_point>                    backgroundScannedAt;
    };

} // namespace invilite::Mesh

#endif // MESH_PROBE_SCHEDULER_H
