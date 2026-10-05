#pragma once

#ifndef MESH_ROUTER_EVENTS_H
#define MESH_ROUTER_EVENTS_H

#include "meshlink/router_wire.h"

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
    };

    // Observer for Router deliveries. Callbacks fire on the Router thread, which serves every peer: listeners MUST be
    // fast and non-blocking (enqueue and return), and MUST NOT call Router::stop() (it joins the very thread running the
    // callback). Exceptions are caught per listener. Default implementations are empty.
    class RouterEventListener {
    public:
        virtual ~RouterEventListener() = default;

        virtual void onMessageDelivered(const RoutedDelivery& delivery) { (void)delivery; }
        virtual void onAckReceived(const AckReceipt& receipt) { (void)receipt; }
    };

} // namespace invilite::Mesh

#endif // MESH_ROUTER_EVENTS_H
