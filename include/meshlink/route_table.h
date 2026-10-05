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

    // How we know a route — only from messages signed by the destination itself (D5): a relay can suggest a bad route,
    // never make one look confirmed
    enum class RouteEvidence : uint8_t {
        Broadcast = 0,                                                              // the destination's broadcast came in over this neighbor
        Ack       = 1,                                                              // the destination's ACK came in over it: a round trip worked
    };

    struct RouteCandidate {
        PeerId                                  via{};                              // neighbor to hand the message to
        uint8_t                                 hops = 0;                           // to the destination, 1 = the neighbor itself
        RouteEvidence                           evidence = RouteEvidence::Broadcast;    // strongest seen for this neighbor
        std::chrono::steady_clock::time_point   lastConfirmedAt;
        std::optional<std::chrono::milliseconds> rtt;                               // smoothed, from ACKs
    };

    struct RouteTableConfig {
        size_t  candidatesPerDestination = 3;
        size_t  maxDestinations          = 4096;                                    // identities are free to mint: memory is bounded, least recently heard first
    };

    // Point-to-point routes learned from traffic (docs/router.md 4.4): per destination a few neighbors it was heard
    // through. A route does not expire with time — it is taken to work until the neighbor leaves, an error says
    // otherwise, or newer data replaces it. Pure data: no threads, no Network; time comes in as `now`.
    // Not thread-safe: owned by the Router thread.
    class RouteTable {
    public:
        explicit RouteTable(RouteTableConfig config = {});

        // `destination` reached us over `via` in `hops`. Newer data for the same neighbor replaces hops and refreshes
        // the entry; an ACK-confirmed neighbor stays confirmed; an RTT is smoothed into the previous one.
        void learn(const PeerId& destination, const PeerId& via, uint8_t hops, RouteEvidence evidence, std::chrono::steady_clock::time_point now,
                   std::optional<std::chrono::milliseconds> rtt = std::nullopt);

        // Neighbors to try for `destination`, best first: ACK-confirmed, then fewer hops, then lower RTT, then most
        // recently confirmed. `excluded` (where the message came from) is left out.
        [[nodiscard]] std::vector<PeerId> nextHops(const PeerId& destination, const std::optional<PeerId>& excluded = std::nullopt) const;

        [[nodiscard]] std::vector<RouteCandidate> candidates(const PeerId& destination) const;   // best first (diagnostics, tests)

        void forgetNeighbor(const PeerId& via);                                     // it disconnected: every route through it is gone
        void forgetRoute(const PeerId& destination, const PeerId& via);             // an error says this one does not work (R-6)

        [[nodiscard]] size_t destinationCount() const { return this->byDestination.size(); }

    private:
        struct Destination {
            std::vector<RouteCandidate>             candidates;                     // kept best first
            std::list<PeerId>::iterator             recency;                        // position in leastRecentFirst
        };

        void eraseDestination(std::unordered_map<PeerId, Destination, PeerIDHash>::iterator entry);

        RouteTableConfig                                        config;
        std::unordered_map<PeerId, Destination, PeerIDHash>    byDestination;
        std::list<PeerId>                                       leastRecentFirst;   // destinations by last time anything was learned
    };

} // namespace invilite::Mesh

#endif // MESH_ROUTE_TABLE_H
