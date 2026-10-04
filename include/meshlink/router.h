#pragma once

#ifndef MESH_ROUTER_H
#define MESH_ROUTER_H

#include "meshlink/peer_directory.h"                                         // PeerIDHash

#include <atomic>
#include <memory>
#include <mutex>
#include <thread>
#include <unordered_set>
#include <vector>

namespace invilite::Mesh {

    class Network;
    struct NetworkMessage;

    // Router (docs/router.md): delivers messages beyond direct neighbors — broadcast to every node, or to one node by
    // per-hop decisions, source route or flood. Sits on top of Network: receives through a NetworkEventListener and sends
    // with Network::sendToPeer. Network knows nothing about the Router beyond the reserved Group 0xFE.
    //
    // Threading: one Router thread owns all routing state. Network's threads only push events into the Router's queue and
    // return — the Router never runs on, and never blocks, a Network thread. The Router thread itself is shared by every
    // peer, so it must never block either (sends are non-blocking since B7).
    //
    // Lifetime: stop() before the Network is destroyed; Network keeps only the queue-owning listener alive, so a late
    // event after stop() lands in a queue nobody drains instead of touching a destroyed Router.
    class Router {
    public:
        explicit Router(Network& network);
        ~Router();

        Router(const Router&)            = delete;
        Router& operator=(const Router&) = delete;

        // Registers with Network and starts the Router thread. Peers already connected become neighbors right away.
        void start();
        void stop();

        // Directly connected peers as the Router sees them (its own view, updated from Network events)
        std::vector<PeerId> getNeighbors() const;

    private:
        class EventInbox;                                                           // NetworkEventListener → Router queue
        struct Event;

        void routerLoop();
        void processEvent(Event& event);
        void handleRouterControl(const NetworkMessage& message);                   // Group 0xFE, neighbor-only
        void handleRoutedMessage(const NetworkMessage& message);                   // Group 0x00..0xFD, routing header

        Network&                                    network;
        std::shared_ptr<EventInbox>                 inbox;
        std::thread                                 routerThread;
        std::atomic<bool>                           running{false};

        // Written by the Router thread (and by start() before the thread runs); read by getNeighbors()
        mutable std::mutex                          neighborsMutex;
        std::unordered_set<PeerId, PeerIDHash>      neighbors;
    };

} // namespace invilite::Mesh

#endif // MESH_ROUTER_H
