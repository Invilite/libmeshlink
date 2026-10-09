#pragma once

#ifndef MESH_ROUTE_TABLE_H
#define MESH_ROUTE_TABLE_H

#include "meshlink/peer_directory.h"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <list>
#include <optional>
#include <unordered_map>
#include <vector>

namespace invilite::Mesh {

    // Standing of a candidate, best first Only messages signed by the destination count.
    enum class RouteTier : uint8_t {
        Measured  = 0,                                                              // our round-trip probe through this neighbor came back over it
        Delivered = 1,                                                              // an ACK answered a message we handed this neighbor
        Hinted    = 2,                                                              // the destination's signed message came in over it; the destination is somewhere behind it
        Failing   = 3,                                                              // the last measurement or awaited ACK failed
    };

    struct RouteCandidate {
        PeerId                                      via{};
        uint8_t                                     hops = 0;                       // to the destination, 1 = the neighbor itself; from unsigned TTL, a hint
        std::chrono::steady_clock::time_point       lastHeardAt;                    // latest hint, delivery or measurement
        uint32_t                                    deliveries = 0;                 // ACKs for our messages sent through it
        std::optional<std::chrono::milliseconds>    rtt;                            // round-trip probe through it, smoothed
        std::optional<std::chrono::steady_clock::time_point> measuredAt;
        uint8_t                                     failures = 0;                   // in a row; a success clears them

        [[nodiscard]] RouteTier tier() const;
    };

    struct RouteTableConfig {
        size_t  candidatesPerDestination = 3;
        size_t  maxDestinations          = 4096;                                    // identities are free to mint: memory is bounded, least recently heard first
        uint8_t failuresToForget         = 3;
    };

    // Point-to-point routes learned from traffic: per destination a few neighbors it was heard through. A route does
    // not expire with time: it is taken to work until the neighbor leaves, an error says otherwise, or newer data
    // replaces it. Pure data (time comes in as `now`).
    // Not thread-safe: owned by the Router thread.
    class RouteTable {
    public:
        explicit RouteTable(RouteTableConfig config = {});

        // A hint: a message signed by `destination` came in over `via`, `hops` away. Refreshes, or adds the candidate when
        // there is room (or it beats the worst); never touches deliveries or measurements.
        void learn(const PeerId& destination, const PeerId& via, uint8_t hops, std::chrono::steady_clock::time_point now);

        // The destination acknowledged a message we handed `via`: it works, maybe not symmetrically.
        // A direct neighbor (`via` == `destination`) is added if missing; anyone else must already be a candidate.
        void recordDelivery(const PeerId& destination, const PeerId& via, std::chrono::steady_clock::time_point now);

        // Our probe through `via` came back the same way: `rtt` for the whole loop, `hops` as recorded. Adds the
        // candidate when missing (a measured route is worth more than any hint).
        void recordMeasurement(const PeerId& destination, const PeerId& via, uint8_t hops, std::chrono::milliseconds rtt, std::chrono::steady_clock::time_point now);

        // A measurement failed, or an awaited ACK did not come. Removes the candidate after failuresToForget in a row.
        void recordFailure(const PeerId& destination, const PeerId& via);

        // Neighbors to try for `destination`, best first (RouteTier, then RTT / hops / failures). `excluded` (where the
        // message came from) is left out.
        [[nodiscard]] std::vector<PeerId> nextHops(const PeerId& destination, const std::optional<PeerId>& excluded = std::nullopt) const;

        [[nodiscard]] std::vector<RouteCandidate> candidates(const PeerId& destination) const;   // best first (diagnostics, tests)

        void forgetNeighbor(const PeerId& via);                                     // it disconnected: every route through it is gone
        void forgetRoute(const PeerId& destination, const PeerId& via);             // an error says this one does not work

        [[nodiscard]] size_t destinationCount() const { return this->byDestination.size(); }
        // Destinations ordered by PeerId, a stable order, so consecutive pages neither skip nor repeat
        [[nodiscard]] std::vector<std::pair<PeerId, std::vector<RouteCandidate>>> destinationsPage(size_t offset, size_t count) const;

    private:
        struct Destination {
            std::vector<RouteCandidate>             candidates;                     // kept best first
            std::list<PeerId>::iterator             recency;
        };

        using Destinations = std::unordered_map<PeerId, Destination, PeerIDHash>;

        void eraseDestination(Destinations::iterator entry);
        // The destination's entry, created when `create` (evicting the least recently heard at the limit); marks it heard
        Destination* touch(const PeerId& destination, bool create);
        // Adds `fresh` if there is room or it beats the worst candidate; false when it was not taken
        bool admit(Destination& entry, const RouteCandidate& fresh);

        RouteTableConfig                                        config;
        Destinations                                            byDestination;
        std::list<PeerId>                                       leastRecentFirst;   // destinations by last time anything was learned
    };

} // namespace invilite::Mesh

#endif // MESH_ROUTE_TABLE_H
