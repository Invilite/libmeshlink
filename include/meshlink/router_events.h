#pragma once

#ifndef MESH_ROUTER_EVENTS_H
#define MESH_ROUTER_EVENTS_H

#include "meshlink/router_wire.h"
#include "meshlink/state_report_wire.h"

#include <chrono>

#include <cstdint>
#include <vector>

namespace invilite::Mesh {

    // A routed message delivered to this node's applications. The Router delivers every broadcast; filtering by
    // group / subtype is the application's job (nodes forward services they do not implement — docs/router.md 1).
    struct RoutedDelivery {
        PeerId                  sender{};                                           // originator as the header says — see senderAuthenticated
        uint64_t                msgId   = 0;                                        // sender's message id; (sender, msgId) is unique
        uint8_t                 group   = 0;
        uint16_t                subtype = 0;
        RoutingMode             mode    = RoutingMode::Broadcast;
        uint8_t                 hopsTraveled = 0;                                   // 1 = from a direct neighbor
        // The sender is proven: by its signature (FLOOD / BROADCAST), or by the link when a UNICAST came straight from that
        // neighbor. A UNICAST relayed by others names its sender unverified until E2E (C2).
        bool                    senderAuthenticated = false;
        std::vector<uint8_t>    payload;
    };

    // An ACK for a message this node sent with ACK_REQUESTED: one per destination of a UNICAST, one per node for a
    // broadcast. Signed by the acknowledging node (verified).
    struct AckReceipt {
        uint64_t                    acknowledgedMsgId = 0;
        PeerId                      acknowledgedBy{};
        std::chrono::milliseconds   rtt{0};                                         // from our send to this ACK's arrival
        uint8_t                     hopsTraveled = 0;                               // of the ACK on its way back
        uint8_t                     attempt = 0;                                    // which send it answers: 0 the first, 1–3 retries (R-8 e)
    };

    // No ACK for a message sent with ackRequested, after every retry (docs/router.md 4.4a, R-8 e): it may have arrived
    // all the same (only the ACKs lost), or not
    struct AckMissing {
        PeerId                      destination{};
        uint64_t                    msgId = 0;
        uint8_t                     attempts = 0;                                   // sends made, the first included
    };

    // Answer to Router::recordRoute (diagnostics): the path the probe took and when each relay saw it
    struct RouteReport {
        PeerId                      destination{};
        uint64_t                    probeMsgId = 0;
        std::vector<RouteHop>       hops;                                           // relays in order; offsets in ms after sending (synchronized clocks)
        uint32_t                    receivedOffsetMs = 0;                           // at the destination
        std::chrono::milliseconds   rtt{0};                                         // probe out + report back, our clock only
        std::optional<PeerId>       firstHop;                                       // the neighbor the probe was handed to, when one
        bool                        returnedSameWay = false;                        // the report came back over the reversed route: a measurement (docs/router.md 4.4a)
    };

    // A message we sent along a source route (Router::sendAlongRoute) did not get through: a relay of the route reported
    // that it could not hand it on (ROUTE_ERROR, signed by that relay), or our own send to the first hop failed. When the
    // next hop was no neighbor, the route we had learned through the first hop is dropped as well; a refused send (full
    // queue, message too large) leaves it.
    struct RouteFailure {
        PeerId              destination{};
        uint64_t            msgId = 0;
        PeerId              reportedBy{};                                           // the relay that could not go on (this node if the first hop failed)
        PeerId              unreachableHop{};                                       // the next hop it could not reach
        RouteErrorReason    reason = RouteErrorReason::NextHopNotNeighbor;
    };

    // A node's answer to our STATE_QUERY (docs/router.md 4.6); our own node answers locally with rtt 0
    struct StateReportReceipt {
        PeerId                          from{};
        uint64_t                        queryMsgId = 0;
        std::chrono::milliseconds       rtt{0};
        StateReportWire::StateReport    report;
    };

    // Observer for Router deliveries. Callbacks fire on the Router thread, which serves every peer: listeners MUST be
    // fast and non-blocking (enqueue and return), and MUST NOT call Router::stop() (it joins the very thread running the
    // callback). Exceptions are caught per listener. Default implementations are empty.
    class RouterEventListener {
    public:
        virtual ~RouterEventListener() = default;

        virtual void onMessageDelivered(const RoutedDelivery& delivery) { (void)delivery; }
        virtual void onAckReceived(const AckReceipt& receipt) { (void)receipt; }
        virtual void onRouteReported(const RouteReport& report) { (void)report; }
        virtual void onRouteFailed(const RouteFailure& failure) { (void)failure; }
        virtual void onStateReported(const StateReportReceipt& receipt) { (void)receipt; }
        virtual void onAckMissing(const AckMissing& missing) { (void)missing; }
    };

} // namespace invilite::Mesh

#endif // MESH_ROUTER_EVENTS_H
