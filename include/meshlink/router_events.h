#pragma once

#ifndef MESH_ROUTER_EVENTS_H
#define MESH_ROUTER_EVENTS_H

#include "meshlink/router_wire.h"

#include <cstdint>
#include <vector>

namespace invilite::Mesh {

    // A routed message delivered to this node's applications. The Router delivers every broadcast; filtering by
    // group / subtype is the application's job (nodes forward services they do not implement — docs/router.md 1).
    struct RoutedDelivery {
        PeerId                  sender{};                                           // verified originator (signature checked for broadcasts)
        uint64_t                msgId   = 0;                                        // sender's message id; (sender, msgId) is unique
        uint8_t                 group   = 0;
        uint16_t                subtype = 0;
        RoutingMode             mode    = RoutingMode::Broadcast;
        uint8_t                 hopsTraveled = 0;                                   // 1 = from a direct neighbor
        std::vector<uint8_t>    payload;
    };

    // Observer for Router deliveries. Callbacks fire on the Router thread, which serves every peer: listeners MUST be
    // fast and non-blocking (enqueue and return), and MUST NOT call Router::stop() (it joins the very thread running the
    // callback). Exceptions are caught per listener. Default implementations are empty.
    class RouterEventListener {
    public:
        virtual ~RouterEventListener() = default;

        virtual void onMessageDelivered(const RoutedDelivery& delivery) { (void)delivery; }
    };

} // namespace invilite::Mesh

#endif // MESH_ROUTER_EVENTS_H
