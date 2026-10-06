#pragma once

#ifndef MESH_HOLE_PUNCH_COORDINATOR_H
#define MESH_HOLE_PUNCH_COORDINATOR_H

#include "meshlink/hole_punch_wire.h"

#include <chrono>
#include <cstddef>
#include <map>
#include <optional>
#include <vector>

namespace invilite::Mesh {

    struct HolePunchCoordinatorConfig {
        std::chrono::milliseconds   exchangeTimeout  = std::chrono::seconds(10);     // REQUEST → NOW at the latest; also how long a nonce is remembered
        std::chrono::milliseconds   requestInterval  = std::chrono::seconds(5);      // one request per neighbor this often — R never becomes an amplifier
        size_t                      maxOpenExchanges = 64;
        bool                        sameNetworkShortcut = true;                     // off only in loopback tests (every node is 127.0.0.1)
    };

    // The common neighbor's side of hole punching (docs/nat-traversal.md 4, role R): passes a request from A to B as an
    // offer carrying A's endpoint as R sees it, and on B's accept tells both sides "now" with the other's endpoint.
    // Coordinates only between its own neighbors, one hop; everything goes over existing authenticated connections.
    // Decides only — Network sends the messages, looks up neighbors and their observed endpoints. Not thread-safe: owned
    // by the Management thread. Time comes in as `now`.
    class HolePunchCoordinator {
    public:
        explicit HolePunchCoordinator(HolePunchCoordinatorConfig config = {});

        // PUNCH_REQUEST from neighbor `requester`, seen by us at `requesterEndpoint`. Endpoints exist only for neighbors
        // that dialed us — their source port is the NAT mapping the punch reuses; nothing when we dialed the requester, or
        // for `targetEndpoint` when the target is not such a neighbor. Returns an offer to the target or a decline to the
        // requester (SameNetwork when both are at one public address); nothing for a nonce already used.
        std::vector<HolePunchMessage> onRequest(const PeerId& requester, const std::optional<HolePunchEndpoint>& requesterEndpoint, const HolePunchRequest& request,
                                                const std::optional<HolePunchEndpoint>& targetEndpoint, std::chrono::steady_clock::time_point now);

        // PUNCH_ACCEPT from `from`: PUNCH_NOW to both sides — only from the target of an open exchange, once
        std::vector<HolePunchMessage> onAccept(const PeerId& from, const HolePunchAccept& accept, std::chrono::steady_clock::time_point now);

        // PUNCH_DECLINE from `from`: forwarded to the requester — only from the target of an open exchange, once
        std::vector<HolePunchMessage> onDecline(const PeerId& from, const HolePunchDecline& decline, std::chrono::steady_clock::time_point now);

        // `peer` is no longer our neighbor: the other side of each of its open exchanges hears PeerLeft
        std::vector<HolePunchMessage> onNeighborLost(const PeerId& peer);

        // Forgets exchanges and request times past their windows (nothing is sent: each side has its own deadline)
        void expire(std::chrono::steady_clock::time_point now);

        [[nodiscard]] size_t openExchangeCount() const;

    private:
        struct Exchange {
            PeerId                                  requester{};
            PeerId                                  target{};
            HolePunchEndpoint                       requesterEndpoint;
            HolePunchEndpoint                       targetEndpoint;
            std::chrono::steady_clock::time_point   deadline{};
            bool                                    finished = false;               // NOW or decline sent; kept until deadline so the nonce is not reused
        };

        // The open exchange `nonce` whose target is `from`, if it may still be answered
        Exchange* findAnswerable(const PeerId& from, const HolePunchNonce& nonce, std::chrono::steady_clock::time_point now);

        const HolePunchCoordinatorConfig                                    config;
        std::map<HolePunchNonce, Exchange>                                  exchanges;
        std::map<PeerId, std::chrono::steady_clock::time_point>             lastRequestAt;
    };

} // namespace invilite::Mesh

#endif // MESH_HOLE_PUNCH_COORDINATOR_H
