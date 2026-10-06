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
        bool                        enabled                     = true;             // off only in tests that count traffic exactly
        double                      probesPerSecond             = 5;                // our own probes, all kinds together
        std::chrono::milliseconds   activeWindow                = std::chrono::seconds(60);    // traffic to a destination this recent makes it active
        std::chrono::milliseconds   activeProbeInterval         = std::chrono::seconds(30);    // each route of an active destination, this often
        std::chrono::milliseconds   backgroundProbeInterval     = std::chrono::minutes(10);    // each known route when traffic is low
        double                      lowTrafficMessagesPerSecond = 10;               // below: background probing
        std::chrono::milliseconds   trafficWindow               = std::chrono::seconds(10);    // the rate is measured over this
        std::chrono::milliseconds   probeTimeout                = std::chrono::seconds(5);     // a probe in flight longer is given up (frees its route)
    };

    // Which routes to measure next (docs/router.md 4.4a, R-8): urgent ones (after a failure, a ROUTE_ERROR, a lost
    // neighbor) before those of active destinations (point-to-point traffic in the last minute, every 30 s) before the
    // background (every known route every 10 min, only while traffic is low). A hard probesPerSecond limit; one probe in
    // flight per (destination, neighbor). Decides only — the Router sends the probes. Not thread-safe: owned by the
    // Router thread. Time comes in as `now`; routes are read from the RouteTable the caller holds.
    class ProbeScheduler {
    public:
        explicit ProbeScheduler(ProbeSchedulerConfig config = {});

        struct Probe {
            PeerId  destination{};
            PeerId  via{};
            bool operator==(const Probe&) const = default;
        };

        // We sent or relayed point-to-point data to `destination`
        void noteTraffic(const PeerId& destination, std::chrono::steady_clock::time_point now);
        // Measure every route to `destination` as soon as the limit allows
        void noteUrgent(const PeerId& destination);
        void noteProbeFinished(const PeerId& destination, const PeerId& via);

        // Destinations with traffic within activeWindow (for the Router: a lost neighbor makes their routes urgent)
        [[nodiscard]] std::vector<PeerId> activeDestinations(std::chrono::steady_clock::time_point now) const;

        // Probes due now, best first, within the limit; each is marked in flight
        std::vector<Probe> takeDueProbes(std::chrono::steady_clock::time_point now, const RouteTable& routes);

    private:
        [[nodiscard]] bool isLowTraffic(std::chrono::steady_clock::time_point now) const;
        [[nodiscard]] bool isInFlight(const Probe& probe) const;
        void refill(std::chrono::steady_clock::time_point now);
        // Routes of `destination` due for a measurement older than `interval` (never measured first), not in flight
        void collectDue(const PeerId& destination, const RouteTable& routes, std::chrono::steady_clock::time_point now,
                        std::chrono::milliseconds interval, std::vector<Probe>& out) const;

        struct ProbeHash { size_t operator()(const Probe& p) const { return PeerIDHash{}(p.destination) ^ (PeerIDHash{}(p.via) << 1); } };

        ProbeSchedulerConfig                                                    config;
        double                                                                  tokens = 0;
        std::optional<std::chrono::steady_clock::time_point>                    refilledAt;
        std::unordered_map<PeerId, std::chrono::steady_clock::time_point, PeerIDHash> lastTrafficAt;
        std::deque<std::chrono::steady_clock::time_point>                       recentTraffic;      // within trafficWindow
        std::deque<PeerId>                                                      urgent;
        std::unordered_map<Probe, std::chrono::steady_clock::time_point, ProbeHash> inFlight;
        std::optional<std::chrono::steady_clock::time_point>                    backgroundScannedAt;
    };

} // namespace invilite::Mesh

#endif // MESH_PROBE_SCHEDULER_H
